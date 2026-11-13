"""Small helpers shared by several test files (not a test file itself: no test_ prefix)."""

from tests.fixtures.events import event
from triage.checks import run_checks

SYS = "C:\\Windows\\System32\\"
PS = SYS + "WindowsPowerShell\\v1.0\\powershell.exe"


def checks_fired(events):
    return {f["check"] for f in run_checks(events)}


def strengths(events, check):
    return [f["strength"] for f in run_checks(events) if f["check"] == check]


def command_findings(image, command):
    """(check, strength) of every finding for one program run with this command line."""
    events = [event(1, 1, "2026-01-05 09:00:00.000", ProcessGuid="{c}", Image=image, CommandLine=command,
                    ParentImage="C:\\Windows\\System32\\cmd.exe")]
    return [(f["check"], f["strength"]) for f in run_checks(events)]
