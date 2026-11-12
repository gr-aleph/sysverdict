"""Generalization test: the same technique with different names must give the same verdict.

renamed() changes every incidental value of a scenario: the user, the computer, file and
program names, domains (a lookalike of another brand), IP addresses, GUIDs and the time.
What the programs DO stays the same. A check that only passes with the original names is
overfit to them and must be rewritten.
"""

from datetime import timedelta

import pytest

from tests.fixtures.events import attack_events, benign_events, event, it_day_events
from triage.checks import make_verdict, run_checks
from triage.parse import to_datetime

# Old text -> new text, applied in this order (longer names first, so "FireEyeInstaller" is
# replaced before "FireEye").
RENAMES = [
    ("analyst", "m.tan"),
    ("LAB-PC01", "DESK-7731"),
    ("FireEyeInstaller", "SecureUpdateSetup"),
    ("FireEye", "SecureUpdate"),
    ("fireeyee", "paypa1"),                       # a lookalike of another brand
    ("video.mp4.exe", "holiday.jpg.exe"),          # another fake document ending
    ("leak.rtf", "salary_2026.rtf"),
    ("leak-site.example.com", "files.example.net"),
    ("Fake Updater", "Print Helper"),
    ("Updater.exe", "SvcHelper.exe"),
    ("Ransom.txt", "HOW_TO_RESTORE.txt"),          # another ransom-note name
    ("167.172.71.11", "91.214.30.17"),             # another public IP
    ("192.168.1.10", "10.20.30.40"),               # another private IP
    ("corp.local", "ad.example.lan"),
    ("Example RMM", "Other Remote Tool"),
    ("agent.exe", "rtagent.exe"),
    ("{", "{z-"),                                  # every GUID changes
]


def renamed(events):
    """A copy of the events with every incidental value changed and the time moved 3 days and
    7 hours later."""
    result = []
    for e in events:
        copy = {}
        for name, value in e.items():
            if isinstance(value, str):
                for old, new in RENAMES:
                    value = value.replace(old, new)
            copy[name] = value
        moved = to_datetime(e["time"]) + timedelta(days=3, hours=7)
        copy["time"] = moved.strftime("%Y-%m-%d %H:%M:%S.%f")[:23]
        result.append(copy)
    return result


def rmm_recon_events():
    """An installed remote-management agent runs whoami and ipconfig through cmd.exe."""
    agent = "C:\\Program Files\\Example RMM\\agent.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    return [
        event(1, 1, "2026-02-01 09:00:00.000", ProcessGuid="{l}", Image=agent),
        event(2, 1, "2026-02-01 09:00:00.500", ProcessGuid="{c}", ParentProcessGuid="{l}",
              Image=cmd, ParentImage=agent),
        event(3, 1, "2026-02-01 09:00:01.000", ProcessGuid="{w}", ParentProcessGuid="{c}",
              Image="C:\\Windows\\System32\\whoami.exe", ParentImage=cmd),
        event(4, 1, "2026-02-01 09:00:02.000", ProcessGuid="{i}", ParentProcessGuid="{c}",
              Image="C:\\Windows\\System32\\ipconfig.exe", ParentImage=cmd),
    ]


SCENARIOS = {"attack": attack_events, "benign": benign_events, "it_day": it_day_events,
             "rmm_recon": rmm_recon_events}


def summary(events):
    """(verdict, {check: strength}) for a list of events."""
    findings = run_checks(events)
    return make_verdict(findings)["label"], {f["check"]: f["strength"] for f in findings}


@pytest.mark.parametrize("name", SCENARIOS)
def test_verdict_is_the_same_with_other_names(name):
    original = SCENARIOS[name]()
    variant = renamed(original)
    assert variant != original                     # the renaming really changed something
    assert summary(variant) == summary(original)


def test_the_renaming_changes_every_name_it_should():
    text = str(renamed(attack_events()))
    for old in ("analyst", "LAB-PC01", "FireEye", "fireeyee", "167.172.71.11", "Ransom.txt"):
        assert old not in text
