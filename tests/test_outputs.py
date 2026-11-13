"""Domains, process tree and timeline."""

from tests.fixtures.events import attack_events, benign_events, event
from triage import graph, story, story_timeline
from triage.checks import run_checks
from triage.domains import classify_domains
from triage.timeline import TIME_ZONES, event_label, group_by_day


def analysed(events):
    findings = run_checks(events)
    return findings, story.build_steps(events, findings)


def test_domain_labels():
    labels = {r["domain"]: r["label"] for r in classify_domains(benign_events())}
    assert labels["www.example-shop.sg"] == "likely visited site"
    assert labels["img-cdn.example.akamaized.net"] == "likely ad, CDN or telemetry"
    assert labels["cdn.example-shop.com"] == "likely page resource"   # 0.7 s after the previous lookup
    assert labels["www.wikipedia.org"] == "likely visited site"       # 90 s of quiet before it
    assert labels["wpad"] == "internal name"


# ---------- process tree ----------

def test_process_tree():
    events = attack_events()
    findings, steps = analysed(events)
    rows = graph.build_process_tree(events, findings, steps)
    by_label = {}
    for row in rows:
        by_label.setdefault(row["label"], row)
    assert by_label["FireEyeInstaller.exe"]["kind"] == "malicious"
    assert "admin rights" in by_label["FireEyeInstaller.exe"]["detail"]
    assert by_label["whoami.exe"]["kind"] == "attack" and by_label["whoami.exe"]["step"] == "Discovery"
    assert any(r["kind"] == "action" and r["label"] == "connects to 167.172.71.11:80" for r in rows)
    # A short label on the left, the long value on the right.
    service = next(r for r in rows if r["label"] == "creates service 'Fake Updater'")
    assert service["kind"] == "action" and service["detail"]
    assert by_label["Updater.exe"]["detail"].endswith("file dropped by video.mp4.exe")
    # The computer is the top line; every other line hangs under it.
    assert rows[0] == {"depth": 0, "kind": "computer", "prefix": "", "label": "LAB-PC01",
                       "time": "", "detail": "", "step": ""}
    assert all(r["depth"] > 0 and r["prefix"] for r in rows[1:])


def test_process_tree_lines():
    events = attack_events()
    findings, steps = analysed(events)
    rows = graph.build_process_tree(events, findings, steps)
    for number, row in enumerate(rows[1:], start=1):
        prefix = row["prefix"]
        # Every line ends with a branch: "├── " (more items follow) or "└── " (the last one).
        assert prefix.endswith(("├── ", "└── "))
        # Four characters per level, so the depth can be read from the prefix.
        assert len(prefix) == 4 * row["depth"]
        # After a "├── ", a later line of the same parent comes before the parent's list ends;
        # so the next line at this depth or deeper keeps a "│" at this column.
        if prefix.endswith("├── "):
            column = len(prefix) - 4
            following = [r for r in rows[number + 1:] if r["depth"] >= row["depth"]]
            assert following and following[0]["prefix"][column] in "│├└"


def test_computer_line_shows_the_name_and_its_own_ip():
    events = [event(1, 3, "2026-01-05 09:00:00.000", Initiated="false", SourceIp="8.8.8.8"),
              event(2, 3, "2026-01-05 09:00:01.000", Initiated="True", SourceIp="10.0.0.5")]  # as Sysmon writes it
    assert graph.computer_line(events) == "LAB-PC01  10.0.0.5"
    assert graph.computer_line(events[:1]) == "LAB-PC01"  # no outgoing connection: name only


def test_process_tree_uses_the_chosen_time_zone():
    events = attack_events()
    findings, steps = analysed(events)
    utc = graph.build_process_tree(events, findings, steps)
    singapore = graph.build_process_tree(events, findings, steps, "Asia/Singapore")  # UTC+8
    timed = [(a["time"], b["time"]) for a, b in zip(utc, singapore) if a["time"]]
    assert timed
    for utc_time, local_time in timed:
        assert (int(utc_time[:2]) + 8) % 24 == int(local_time[:2])
        assert utc_time[2:] == local_time[2:]  # same minutes and seconds


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
    rows = story_timeline.story_rows(events, steps)
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
    assert len(rows) < len(events)  # only the incident's events


def test_timeline_is_empty_without_an_incident():
    assert story_timeline.story_rows(benign_events(), []) == []


def test_timeline_in_local_time():
    events = attack_events()
    findings, steps = analysed(events)
    rows = story_timeline.story_rows(events, steps, "Asia/Singapore")
    # The first incident event is Edge saving the installer at 09:59:50 UTC = 17:59:50 in Singapore.
    assert rows[0]["Local time"] == "2026-01-05 17:59:50" and "Time (UTC)" not in rows[0]
    assert rows[0]["Sysmon Event ID"] == "15 – FileCreateStreamHash"


def test_days_follow_the_chosen_zone():
    items = [{"time": "2026-01-05 22:00:00.000"}, {"time": "2026-01-06 01:00:00.000"}]
    utc = group_by_day(items)
    assert [day for day, _ in utc] == ["Day 1 · Mon 05 Jan 2026", "Day 2 · Tue 06 Jan 2026"]
    singapore = group_by_day(items, "Asia/Singapore")  # both are 6 Jan in Singapore
    assert len(singapore) == 1 and singapore[0][1][0][0] == "06:00:00"


def test_csv_download_opens_correctly_in_excel():
    # Excel only reads a CSV as UTF-8 when it starts with the UTF-8 mark (BOM, bytes EF BB BF);
    # without it, "–" shows as "â€“" and "·" as "Â·".
    from ui_common import csv_bytes
    rows = [{"Sysmon Event ID": "1 – Process Create", "MITRE ATT&CK": "Discovery · T1033"}]
    data = csv_bytes(rows)
    assert data.startswith(b"\xef\xbb\xbf")
    assert data.decode("utf-8-sig") == ("Sysmon Event ID,MITRE ATT&CK\r\n"
                                        "1 – Process Create,Discovery · T1033\r\n")
