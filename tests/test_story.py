"""The attack story: how it got in, the numbered steps, ATT&CK tags and the NIST next steps."""

from tests.fixtures.events import USER, attack_events, benign_events, event
from triage import story
from triage.checks import make_verdict, run_checks


def steps_of(events):
    return story.build_steps(events, run_checks(events))


def recon_chain(program, parent="C:\\Windows\\explorer.exe"):
    """A program that runs whoami + ipconfig (a High-confidence finding), started by parent."""
    return [
        event(1, 1, "2026-01-05 10:00:00.000", ProcessGuid="{x}", ParentProcessGuid="{parent}",
              Image=program, ParentImage=parent, CommandLine=f'"{program}"'),
        event(2, 1, "2026-01-05 10:00:01.000", ProcessGuid="{c1}", ParentProcessGuid="{x}",
              Image="C:\\Windows\\System32\\cmd.exe", ParentImage=program, CommandLine="cmd /c whoami"),
        event(3, 1, "2026-01-05 10:00:01.100", ProcessGuid="{w}", ParentProcessGuid="{c1}",
              Image="C:\\Windows\\System32\\whoami.exe", ParentImage="C:\\Windows\\System32\\cmd.exe"),
        event(4, 1, "2026-01-05 10:00:01.200", ProcessGuid="{i}", ParentProcessGuid="{c1}",
              Image="C:\\Windows\\System32\\ipconfig.exe", ParentImage="C:\\Windows\\System32\\cmd.exe"),
    ]


# ---------- how it got in ----------

def test_browser_download_with_referrer_uac_and_double_click():
    steps = steps_of(attack_events())
    origin, execution = steps[0], steps[1]
    assert origin["tactic"] == "Initial Access" and origin["technique"].startswith("T1189")
    assert "with Edge from https://www.fireeyee.com/download/FireEyeInstaller.exe" in origin["text"]
    assert "from the page https://www.fireeyee.com/" in origin["text"]
    assert "How the user reached that site" in origin["text"]  # no DNS lookup for it in the log
    assert execution["follows"] == 1
    assert "double-clicking" in execution["text"] and "UAC" in execution["text"]


def test_email_attachment():
    program = USER + "\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\AB12\\invoice.exe"
    origin = steps_of(recon_chain(program, "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"))[0]
    assert origin["technique"].startswith("T1566.001")
    assert "email attachment" in origin["text"]


def test_unknown_origin_is_said_plainly():
    origin = steps_of(recon_chain(USER + "\\Desktop\\tool.exe"))[0]
    assert origin["technique"] == ""
    assert "not in this log" in origin["text"]


def test_document_from_the_browser():
    document_chain = [e for e in attack_events() if e["record_id"] >= 200]
    steps = steps_of(benign_events() + document_chain)
    assert "downloaded leak.rtf with Edge from https://www.leak-site.example.com/files/leak.rtf" in steps[0]["text"]
    assert "straight from Edge, which opened it in wordpad.exe" in steps[1]["text"]
    tactics = [s["tactic"] for s in steps]
    assert "Persistence" in tactics and "Impact" in tactics


# ---------- the steps ----------

def test_every_step_has_a_tag_proof_and_a_number():
    events = attack_events()
    ids = {e["record_id"] for e in events}
    steps = steps_of(events)
    assert [s["number"] for s in steps] == list(range(1, len(steps) + 1))
    for s in steps:
        assert s["tactic"] in story.TACTIC_ORDER
        assert s["event_ids"] and set(s["event_ids"]) <= ids
    assert all(s["technique"] for s in steps[1:])


def test_steps_link_to_what_caused_them():
    steps = steps_of(attack_events())
    service = next(s for s in steps if s["technique"].startswith("T1543.003"))
    dropper = next(s for s in steps if s["number"] == service["follows"])
    assert "video.mp4.exe" in dropper["image"]


def test_no_story_for_a_benign_log():
    assert steps_of(benign_events()) == []


def test_key_moments_are_short_and_start_with_how_it_got_in():
    moments = story.key_moments(steps_of(attack_events()))
    assert len(moments) <= 8
    assert moments[0]["tactic"] == "Initial Access" and moments[1]["tactic"] == "Execution"


def test_unrelated_low_findings_are_kept_apart():
    installer = USER + "\\Downloads\\vendor_setup.exe"
    events = attack_events() + [
        event(400, 1, "2026-01-05 12:00:00.000", ProcessGuid="{vendor}", ParentProcessGuid="{p-explorer}",
              Image=installer, ParentImage="C:\\Windows\\explorer.exe", CommandLine=f'"{installer}"')]
    part, other = story.split_low_findings(events, run_checks(events))
    assert any("vendor_setup.exe" in f["process"] for f in other)
    assert not any("vendor_setup.exe" in f["process"] for f in part)
    assert any("FireEyeInstaller.exe" in f["process"] for f in part)


def test_page_shows_real_addresses_as_code_text():
    text = "Edge saved FireEye.exe from https://www.fireeyee.com/a.exe, then called 167.172.71.11:80"
    assert story.code_addresses(text) == ("Edge saved FireEye.exe from `https://www.fireeyee.com/a.exe`, "
                                          "then called `167.172.71.11:80`")
    assert story.code_addresses("version 10.0.22621.1") == "version 10.0.22621.1"


def test_defang_makes_links_unclickable_but_keeps_file_names():
    text = "Edge saved FireEye.exe from https://www.fireeyee.com/a.exe, then called 167.172.71.11:80"
    assert story.defang(text) == ("Edge saved FireEye.exe from hxxps://www[.]fireeyee[.]com/a.exe, "
                                  "then called 167[.]172[.]71[.]11:80")
    assert story.defang("version 10.0.22621.1") == "version 10.0.22621.1"


# ---------- next steps ----------

def test_next_steps_use_nist_phases():
    events = attack_events()
    findings = run_checks(events)
    plan = story.next_steps(findings, make_verdict(findings), story.build_steps(events, findings))
    assert list(plan) == [p for p in story.PHASES if p in plan]
    assert {"Investigate", "Contain", "Eradicate", "Recover"} <= set(plan)
    assert any("www.fireeyee.com" in step for step in plan["Contain"])


def test_benign_next_steps_are_investigate_only():
    plan = story.next_steps([], make_verdict([]))
    assert list(plan) == ["Investigate"]
    assert plan["Investigate"][0].startswith("No action needed")
