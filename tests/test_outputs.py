"""Domains, process tree, timeline and PDF."""

from tests.fixtures.events import attack_events, benign_events
from triage import graph, report, story
from triage.checks import make_verdict, run_checks
from triage.domains import classify_domains
from triage.iocs import extract_iocs
from triage.timeline import TIME_ZONES, event_label, group_by_day


def analysed(events):
    findings = run_checks(events)
    return findings, story.build_steps(events, findings)


def test_domain_labels():
    labels = {r["domain"]: r["label"] for r in classify_domains(benign_events())}
    assert labels["www.lazada.sg"] == "likely visited site"
    assert labels["lzd-img-global.slatic.net"] == "likely ad, CDN or telemetry"
    assert labels["cdn.example-shop.com"] == "likely page resource"   # 0.7 s after the previous lookup
    assert labels["www.wikipedia.org"] == "likely visited site"       # 90 s of quiet before it
    assert labels["wpad"] == "internal name"


# ---------- process tree ----------

def test_indented_process_tree():
    events = attack_events()
    findings, steps = analysed(events)
    rows = graph.build_process_tree(events, findings, steps)
    by_label = {}
    for row in rows:
        by_label.setdefault(row["label"], row)
    assert by_label["FireEyeInstaller.exe"]["kind"] == "malicious"
    assert "admin rights" in by_label["FireEyeInstaller.exe"]["meta"]
    assert by_label["whoami.exe"]["kind"] == "attack" and by_label["whoami.exe"]["step"] == "Discovery"
    assert any(r["kind"] == "action" and r["label"].startswith("connects to 167.172.71.11:80") for r in rows)
    assert any(r["kind"] == "action" and r["label"].startswith("creates service 'Fake Updater'") for r in rows)
    assert by_label["Updater.exe"]["meta"].endswith("file dropped by video.mp4.exe")
    # the normal parent program is at the top; everything else is indented under it
    assert rows[0]["depth"] == 0 and rows[0]["kind"] == "context"
    assert all(r["depth"] > 0 for r in rows if r["kind"] != "context")


def test_no_process_tree_for_a_benign_log():
    assert graph.build_process_tree(benign_events(), [], []) == []


# ---------- time and raw events ----------

def test_us_time_zones_are_offered():
    assert TIME_ZONES["Dallas, TX (US Central)"] == "America/Chicago"
    assert TIME_ZONES["Los Angeles, CA (US Pacific)"] == "America/Los_Angeles"


def test_sysmon_event_labels():
    assert event_label(1) == "1 – Process Create"
    assert event_label(22) == "22 – DNSEvent (DNS query)"


def test_timeline_table_tells_the_story_in_a_column():
    events = attack_events()
    findings, steps = analysed(events)
    rows = story.story_rows(events, steps)
    assert list(rows[0]) == ["Time (UTC)", "Sysmon Event ID", "MITRE ATT&CK", "Event", "Event #"]
    tags = [r["MITRE ATT&CK"] for r in rows]
    assert "Discovery · T1033 System Owner/User Discovery" in tags
    assert all(tags)  # every story row has a tactic
    stories = [r["Event"] for r in rows]
    assert any("saved FireEyeInstaller.exe, downloaded from https://www.fireeyee.com" in s for s in stories)
    assert any("admin approval prompt (UAC)" in s for s in stories)
    assert any("ran whoami.exe, which shows the logged-on user" in s for s in stories)
    assert any("dropped C:\\Windows\\System32\\Updater.exe, which runs later" in s for s in stories)
    assert any("opened C:\\Ransom.txt in Notepad" in s for s in stories)
    assert len(rows) < len(events)  # by default only the story's events


def test_timeline_table_all_events_and_local_time():
    events = benign_events()
    rows = story.story_rows(events, [], "Asia/Singapore", include_all=True)
    assert len(rows) == len(events)
    assert rows[0]["MITRE ATT&CK"] == ""  # not part of an attack
    assert rows[0]["Local time"] == "2026-01-05 17:00:00" and "Time (UTC)" not in rows[0]
    assert rows[0]["Sysmon Event ID"] == "1 – Process Create"


def test_days_follow_the_chosen_zone():
    items = [{"time": "2026-01-05 22:00:00.000"}, {"time": "2026-01-06 01:00:00.000"}]
    utc = group_by_day(items)
    assert [day for day, _ in utc] == ["Day 1 · Mon 05 Jan 2026", "Day 2 · Tue 06 Jan 2026"]
    singapore = group_by_day(items, "Asia/Singapore")  # both are 6 Jan in Singapore
    assert len(singapore) == 1 and singapore[0][1][0][0] == "06:00:00"


# ---------- PDF ----------

def test_pdf_is_built():
    events = attack_events()
    findings, steps = analysed(events)
    verdict = make_verdict(findings)
    pdf = report.build_pdf("lab.evtx", verdict, steps, story.key_moments(steps),
                           story.next_steps(findings, verdict, steps), findings,
                           extract_iocs(events, findings), {})
    assert pdf.startswith(b"%PDF") and len(pdf) > 10_000


def test_pdf_for_a_benign_log():
    pdf = report.build_pdf("clean.evtx", make_verdict([]), [], [], story.next_steps([], make_verdict([])),
                           [], [], {})
    assert pdf.startswith(b"%PDF")
