"""The checks and the verdict: benign activity stays Benign, attack activity is caught."""

import base64

from tests.fixtures.events import USER, attack_events, benign_events, event
from triage.checks import make_verdict, run_checks
from triage.checks_c2 import edit_distance
from triage import parse
from triage.parse import event_from_xml


def checks_fired(events):
    return {f["check"] for f in run_checks(events)}


# ---------- false positives: normal activity must not be flagged ----------

def test_edge_run_key_and_onedrive_are_known_good():
    assert "persistence" not in checks_fired(benign_events())
    assert "run_from_user_folder" not in checks_fired(benign_events())


# ---------- the attack is caught ----------

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
    # Dual-use gate: an installed program with no other sign is Low; a Downloads program is High.
    assert [f["strength"] for f in run_checks(fake)] == ["Weak"]
    fake[0]["Image"] = USER + "\\Downloads\\setup.exe"
    assert [f["strength"] for f in run_checks(fake) if f["check"] == "lookalike_domain"] == ["Strong"]


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


def powershell_strengths(command, parent=USER + "\\Downloads\\invoice_viewer.exe"):
    """The strengths of the PowerShell findings for one command line, started by parent
    (by default a program in Downloads, which is not an admin tool)."""
    events = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{ps}", ParentProcessGuid="{parent}",
                    Image=PS, ParentImage=parent, CommandLine=command)]
    return [f["strength"] for f in run_checks(events) if f["check"] == "suspicious_powershell"]


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


def test_ransom_words_in_a_program_file_are_not_a_note():
    python = "C:\\Python314\\python.exe"
    events = [event(1, 11, "2026-01-05 09:00:00.000", Image=python,
                    TargetFilename="C:\\Python314\\Lib\\site-packages\\Crypto\\decrypt_test.py")]
    assert "ransom_note" not in checks_fired(events)


# ---------- verdict and helpers ----------

def test_edit_distance():
    assert edit_distance("fireeyee", "fireeye") == 1
    assert edit_distance("gmailc", "gmail") == 1
    assert edit_distance("google", "google") == 0


