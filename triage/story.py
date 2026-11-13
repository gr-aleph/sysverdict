"""The attack story, built from templates (no AI, nothing leaves the machine).

The story is a numbered list of steps. Each step is a plain dict:

    {"number": 3, "time": "2023-12-13 10:53:39.908",
     "tactic": "Discovery", "technique": "T1033 System Owner/User Discovery",   # MITRE ATT&CK
     "text": "The installer ran whoami.exe, ipconfig.exe within 60 seconds ...",  # plain English
     "technical": "Sysmon 1 – Process Create · cmd.exe /c whoami",               # for the analyst
     "confidence": "High",               # High / Low, or "" for how-it-got-in steps
     "event_ids": [16713, 16715],        # the proof
     "guid": "{...}", "image": "c:\\...\\fireeye.exe"}

How it is built:
  1. find_delivery()  - how the first malicious file got onto the computer and who started it
     (story_delivery.py)
  2. one step per finding that belongs to the attack (High, and Low ones of the same programs),
     worded with the ATT&CK tags and sentences in story_text.py
  3. sort them by time and number them 1, 2, 3, ...
The Timeline rows are in story_timeline.py, the next steps in story_next_steps.py.
"""

from triage.checks_common import file_name
from triage.display import display_name
from triage.story_delivery import attack_processes, find_delivery
from triage.story_text import ATTACK_TAGS, CONFIDENCE, RECON_TECHNIQUES, SENTENCES
from triage.timeline import event_label


def split_low_findings(events, findings):
    """Return (Low findings that belong to the attack, other Low findings)."""
    guids, images = attack_processes(events, findings)
    has_strong = any(f["strength"] == "Strong" for f in findings)
    part, other = [], []
    for f in findings:
        if f["strength"] != "Weak":
            continue
        belongs = has_strong and (f["process_guid"] in guids or f["process"].lower() in images)
        (part if belongs else other).append(f)
    return part, other


def tag_key(finding):
    if finding["check"] == "persistence":
        return "persistence_service" if "service" in finding["title"].lower() else "persistence_run_key"
    return finding["check"]


def finding_step(f, events_by_id):
    key = tag_key(f)
    tactic, technique = ATTACK_TAGS[key]
    if f.get("technique"):  # the command-line checks give the exact tag of the rule that matched
        tactic, technique = f["tactic"], f["technique"]
    if f["check"] == "lookalike_domain" and f["strength"] == "Weak":
        tactic, technique = "Initial Access", "T1566.002 Spearphishing Link (possible)"
    first = events_by_id[f["event_ids"][0]]  # the finding's earliest event
    if f["check"] == "recon_burst":
        technique = RECON_TECHNIQUES.get(file_name(first.get("Image")), technique)
    text = SENTENCES[key].format(detail=f["detail"], process=display_name(f["process"]))
    if f["check"] == "run_from_user_folder" and first.get("ParentImage"):
        starter = display_name(first["ParentImage"])
        text += " The user started it again (by double-clicking it)." if starter.lower() == "explorer.exe" \
            else f" It was started by {starter}."
    target = (first.get("CommandLine") or first.get("TargetObject") or first.get("TargetFilename")
              or first.get("QueryName") or first.get("DestinationIp") or "")
    return {"time": f["time"], "tactic": tactic, "technique": technique,
            "text": text,
            "technical": f"{event_label(first['event_id'])} · {display_name(first.get('Image'))} · {target[:160]}",
            "event_ids": f["event_ids"], "guid": f["process_guid"], "image": f["process"].lower(),
            "confidence": CONFIDENCE[f["strength"]], "kind": "finding", "check": f["check"]}


def build_steps(events, findings):
    """The numbered attack story (empty when nothing High-confidence or Low was found)."""
    if not findings:
        return []
    events_by_id = {e["record_id"]: e for e in events}
    part_low, _ = split_low_findings(events, findings)
    has_strong = any(f["strength"] == "Strong" for f in findings)
    chosen = [f for f in findings if f["strength"] == "Strong"] + part_low if has_strong else list(findings)

    steps = find_delivery(events, findings) if has_strong else []
    started = {s["image"] for s in steps if s["kind"] == "execution"}
    for f in chosen:
        # The first run is already told by the delivery step.
        if f["check"] == "run_from_user_folder" and f["process"].lower() in started:
            continue
        steps.append(finding_step(f, events_by_id))
    # A Low step whose events are all told by a High step adds nothing: drop it.
    told = {i for s in steps if s["confidence"] == "High" for i in s["event_ids"]}
    steps = [s for s in steps if not (s["confidence"] == "Low" and set(s["event_ids"]) <= told)]
    steps.sort(key=lambda s: (s["time"], s["kind"] != "origin"))

    for number, step in enumerate(steps, start=1):
        step["number"] = number
    return steps


def key_moments(steps, limit=8):
    """The short version for the Summary: how it got in, then the first step of each tactic."""
    chosen, seen = [], set()
    for step in steps:
        if step["kind"] in ("origin", "execution") or step["tactic"] not in seen:
            chosen.append(step)
            seen.add(step["tactic"])
    return chosen[:limit]
