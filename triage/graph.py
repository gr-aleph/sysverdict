"""The Process tree tab: an indented "who started what" list of the attack processes,
like the process view of an EDR tool.

build_process_tree() returns plain rows; app.py draws them as HTML (each row indented by its depth).
"""

from triage.story import attack_processes, display_name

MAX_TREE_LINES = 80  # a very long tree is cut here so the page stays fast


def action_text(e):
    """What a process did, as one short line (None for events not worth a line)."""
    event_id = e["event_id"]
    if event_id == 3:
        return f"connects to {e.get('DestinationIp')}:{e.get('DestinationPort')}"
    if event_id == 22:
        return f"looks up {e.get('QueryName', '').rstrip('.')}"
    if event_id == 11:
        return f"drops {e.get('TargetFilename', '')}"
    if event_id in (12, 13):
        key_name = e.get("TargetObject", "").split("\\")
        if key_name[-1].lower() == "imagepath":
            return f"creates service '{key_name[-2]}' -> {e.get('Details', '')}"
        return f"sets Run key '{key_name[-1]}' -> {e.get('Details', '')}"
    if event_id == 10:
        return f"opens the memory of {display_name(e.get('TargetImage'))}"
    return None


def build_process_tree(events, findings, steps):
    """Rows for the process tree. Each row is a dict:

        {"depth": 0, 1, 2, ... (how far it is indented),
         "kind": "context" (normal program that started the attack) / "malicious" / "attack" / "action",
         "label": "FireEye.exe", "detail": "command line", "meta": "10:53:39 · admin rights",
         "step": "Discovery" (the ATT&CK tactic of its story step, or "")}
    """
    if not steps:
        return []

    # ---- 1. Look-up tables, built once ----

    # Every process that was started in this log (Sysmon event 1), by its ProcessGuid.
    processes = {}
    for e in events:
        if e["event_id"] == 1 and e.get("ProcessGuid"):
            processes[e["ProcessGuid"]] = e

    # The ProcessGuids of the attack's processes.
    attack, _ = attack_processes(events, findings)

    # Processes with a High-confidence finding are "malicious" (shown in red).
    malicious_guids = set()
    malicious_files = set()
    for f in findings:
        if f["strength"] == "Strong":
            malicious_guids.add(f["process_guid"])
            # Another run of the same file is malicious too, unless it is a Windows program.
            if f["process"] and not f["process"].lower().startswith("c:\\windows\\"):
                malicious_files.add(f["process"].lower())

    # The ATT&CK tactic of each story event, and of each story process.
    tactic_of_event = {}
    tactic_of_process = {}
    for s in steps:
        for event_id in s["event_ids"]:
            tactic_of_event.setdefault(event_id, s["tactic"])
        if s["guid"]:
            tactic_of_process.setdefault(s["guid"], s["tactic"])

    # Which program dropped (created) each file.
    dropped_by = {}
    for e in events:
        if e["event_id"] == 11:
            dropped_by[e.get("TargetFilename", "").lower()] = display_name(e.get("Image"))

    # The attack processes each process started, in time order.
    children = {}
    for guid, p in processes.items():
        if guid in attack:
            children.setdefault(p.get("ParentProcessGuid"), []).append(guid)

    # What each process did that is part of the story (and every program it dropped).
    # The same line twice under one process is shown once.
    actions = {}
    for e in events:
        guid = e.get("ProcessGuid")
        if e["event_id"] == 1 or not guid:
            continue
        drops_program = (e["event_id"] == 11 and guid in attack
                         and e.get("TargetFilename", "").lower().endswith((".exe", ".dll")))
        if e["record_id"] in tactic_of_event or drops_program:
            text = action_text(e)
            already_there = [line for line, _ in actions.get(guid, [])]
            if text and text not in already_there:
                actions.setdefault(guid, []).append((text, e))

    # ---- 2. The rows ----

    rows = []

    def add_actions(guid, depth):
        """One row per action of this process."""
        for text, e in actions.get(guid, []):
            rows.append({"depth": depth, "kind": "action", "label": text, "detail": "",
                         "meta": e["time"][11:19], "step": tactic_of_event.get(e["record_id"], "")})

    def process_row(guid, depth):
        """The row for one process: its name, command line, time and labels."""
        p = processes[guid]
        image = p.get("Image", "")
        if guid not in attack:
            kind = "context"  # a normal program that started the attack
        elif guid in malicious_guids or image.lower() in malicious_files:
            kind = "malicious"
        else:
            kind = "attack"

        meta = [p["time"][11:19]]
        if p.get("IntegrityLevel") in ("High", "System"):
            meta.append("admin rights")
        if kind == "malicious" and image.lower() in dropped_by:
            meta.append(f"file dropped by {dropped_by[image.lower()]}")

        # Show the command line, unless it is only the program's own path.
        command = p.get("CommandLine", "").strip()
        detail = "" if command.strip('"').lower() == image.lower() else command[:160]

        return {"depth": depth, "kind": kind, "label": display_name(image), "detail": detail,
                "meta": " · ".join(meta),
                "step": tactic_of_event.get(p["record_id"], "") or tactic_of_process.get(guid, "")}

    def add_process(guid, depth):
        """One row for this process, then its actions, then each child process the same way
        (this function calls itself for the children, one level deeper)."""
        if len(rows) >= MAX_TREE_LINES:
            return
        rows.append(process_row(guid, depth))
        add_actions(guid, depth + 1)
        for child in children.get(guid, []):
            add_process(child, depth + 1)

    # The attack starts with processes whose parent is a normal program (e.g. explorer.exe).
    # Show that parent once at the top, and the attack processes below it.
    roots_by_parent = {}
    for guid, p in processes.items():
        parent = p.get("ParentProcessGuid")
        if guid in attack and parent not in attack:
            roots_by_parent.setdefault(parent, []).append(guid)

    for parent, roots in roots_by_parent.items():
        if parent in processes:
            rows.append(process_row(parent, 0))
        else:  # the parent was started before this log began: we only know its name
            rows.append({"depth": 0, "kind": "context",
                         "label": display_name(processes[roots[0]].get("ParentImage", "?")),
                         "detail": "(started before this log)", "meta": "", "step": ""})
        add_actions(parent, 1)
        for root in roots:
            add_process(root, 1)
    return rows
