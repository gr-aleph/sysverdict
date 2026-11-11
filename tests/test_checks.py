"""The checks and the verdict: benign activity stays Benign, attack activity is caught."""

from tests.fixtures.events import attack_events, benign_events, event
from triage.checks import edit_distance, make_verdict, run_checks
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
