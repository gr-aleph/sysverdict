"""Changes on the computer itself: persistence (Run keys, services), credential theft (LSASS,
cookies) and weakened defences (Defender, UAC). Every name here is made up (analyst, example paths)."""

from tests.fixtures.events import USER, attack_events, benign_events, event
from tests.helpers import SYS, checks_fired, command_findings, strengths
from triage.checks import run_checks


# ---------- persistence ----------

def test_edge_run_key_and_onedrive_are_known_good():
    assert "persistence" not in checks_fired(benign_events())
    assert "run_from_user_folder" not in checks_fired(benign_events())


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


def test_discord_run_key_is_known_good():
    discord = "C:\\Users\\analyst\\AppData\\Local\\Discord\\app-1.0.9\\Discord.exe"
    events = [event(1, 13, "2026-01-05 09:00:00.000", Image=discord,
                    TargetObject="HKU\\S-1-5-21-0\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Discord",
                    Details='"C:\\Users\\analyst\\AppData\\Local\\Discord\\Update.exe" --processStart Discord.exe')]
    assert "persistence" not in checks_fired(events)


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


# ---------- credentials: LSASS and browser cookies ----------

LSASS = "C:\\Windows\\system32\\lsass.exe"


def test_lsass_access_from_unknown_program_is_strong():
    events = [event(1, 10, "2026-01-05 09:00:00.000", SourceImage="C:\\Users\\a\\Downloads\\tool.exe",
                    TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1010"),
              event(2, 10, "2026-01-05 09:00:01.000", SourceImage="C:\\Windows\\system32\\svchost.exe",
                    TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1000")]
    findings = run_checks(events)
    assert [f["check"] for f in findings] == ["lsass_access"]
    assert findings[0]["event_ids"] == [1]


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


def test_lsass_reader_in_windows_temp_is_strong():
    fake = "C:\\Windows\\Temp\\wininit.exe"
    events = [event(1, 10, "2026-02-01 09:00:00.000", SourceImage=fake, SourceProcessGUID="{f}",
                    TargetImage=SYS + "lsass.exe", GrantedAccess="0x1fffff")]
    assert strengths(events, "lsass_access") == ["Strong"]


def test_deleting_cookies_is_not_theft_but_copying_them_is():
    cookies = USER + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"
    delete = [event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{d}", Image=SYS + "cmd.exe",
                    CommandLine=f'cmd /c del /f "{cookies}"')]
    copy = [event(2, 1, "2026-02-01 09:00:00.000", ProcessGuid="{c}", Image=SYS + "cmd.exe",
                  CommandLine=f'cmd /c copy "{cookies}" C:\\Users\\Public\\c.db')]
    assert "credential_theft" not in checks_fired(delete)
    assert strengths(copy, "credential_theft") == ["Strong"]


# ---------- weakened defences: Defender and UAC ----------

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


def test_uac_bypass_key_in_the_classes_form_is_strong():
    events = [event(1, 13, "2026-02-01 09:00:00.000", ProcessGuid="{u}", Image=USER + "\\Downloads\\u.exe",
                    TargetObject="HKU\\S-1-5-21-0_Classes\\ms-settings\\shell\\open\\command\\(Default)",
                    Details="C:\\Users\\Public\\u.exe")]
    assert strengths(events, "uac_bypass") == ["Strong"]
