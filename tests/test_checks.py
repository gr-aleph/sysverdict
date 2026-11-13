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

# ---------- the attack is caught ----------

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


def test_office_spawning_powershell():
    events = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{x}", ParentProcessGuid="{w}",
                    Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    ParentImage="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                    CommandLine="powershell -nop")]
    assert "document_app_spawns_program" in checks_fired(events)


# ---------- fewer false "Malicious" verdicts ----------

LSASS = "C:\\Windows\\system32\\lsass.exe"


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


def command_findings(image, command):
    """(check, strength) of every finding for one program run with this command line."""
    events = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{c}", Image=image, CommandLine=command,
                    ParentImage="C:\\Windows\\System32\\cmd.exe")]
    return [(f["check"], f["strength"]) for f in run_checks(events)]


SYS = "C:\\Windows\\System32\\"


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


