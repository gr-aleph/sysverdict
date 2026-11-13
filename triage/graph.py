"""The Process tree tab: an indented "who started what" list of the attack processes,
like the process view of an EDR tool.

build_process_tree() returns plain rows; app.py draws them as HTML (each row indented by its depth).
"""

from triage.display import display_name
from triage.story_delivery import attack_processes
from triage.timeline import in_zone

MAX_TREE_LINES = 80  # a very long tree is cut here so the page stays fast


def action_text(e):
    """What a process did: (short label, details for the right-hand column).
    None for events not worth a line."""
    event_id = e["event_id"]
    if event_id == 3:
        return f"connects to {e.get('DestinationIp')}:{e.get('DestinationPort')}", ""
    if event_id == 22:
        return f"looks up {e.get('QueryName', '').rstrip('.')}", ""
    if event_id == 11:
        return f"drops {display_name(e.get('TargetFilename'))}", e.get("TargetFilename", "")
    if event_id in (12, 13):
        key_name = e.get("TargetObject", "").split("\\")
        if key_name[-1].lower() == "imagepath":
            return f"creates service '{key_name[-2]}'", e.get("Details", "")
        return f"sets Run key '{key_name[-1]}'", e.get("Details", "")
    if event_id == 10:
        return f"opens the memory of {display_name(e.get('TargetImage'))}", ""
    return None


def computer_line(events):
    """The tree's top line: the computer's name and, if the log shows it, its IP address,
    taken from the computer's own outgoing connections (Sysmon event 3, Initiated = true)."""
    names = [e["computer"] for e in events if e.get("computer")]
    name = max(set(names), key=names.count) if names else "This computer"  # the most common name
    for e in events:
        source_ip = e.get("SourceIp", "")
        # Sysmon writes "True"; .lower() also accepts "true".
        if e["event_id"] == 3 and e.get("Initiated", "").lower() == "true" and "." in source_ip \
                and not source_ip.startswith("127."):
            return f"{name}  {source_ip}"
    return name


def build_process_tree(events, findings, steps, zone_name=None):
    """Rows for the process tree, like a timeline tree, with times in the chosen time zone
    (UTC if none). Each row is a dict:

        {"depth": 0, 1, 2, ... (how deep it is in the tree),
         "kind": "computer" (the top line) / "context" (normal program that started the attack) /
                 "malicious" / "attack" / "action",
         "prefix": "│   ├── " (the tree lines drawn before the label),
         "label": "FireEye.exe", "time": "10:53:39",
         "detail": "command line · admin rights" (the right-hand column),
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

    def clock(e):
        """The event's time of day in the chosen zone, e.g. '10:53:39'."""
        return in_zone(e["time"], zone_name).strftime("%H:%M:%S")

    def action_row(text, e, prefix, depth):
        """The row for one action of a process: short label left, details right."""
        label, detail = text
        return {"depth": depth, "kind": "action", "prefix": prefix, "label": label, "time": clock(e),
                "detail": detail, "step": tactic_of_event.get(e["record_id"], "")}

    def process_row(guid, prefix, depth):
        """The row for one process: its name and time; command line and labels on the right."""
        if guid not in processes:
            # The parent was started before this log began: we only know its name.
            first_child = processes[children[guid][0]]
            return {"depth": depth, "kind": "context", "prefix": prefix,
                    "label": display_name(first_child.get("ParentImage", "?")), "time": "",
                    "detail": "(started before this log)", "step": ""}
        p = processes[guid]
        image = p.get("Image", "")
        if guid not in attack:
            kind = "context"  # a normal program that started the attack
        elif guid in malicious_guids or image.lower() in malicious_files:
            kind = "malicious"
        else:
            kind = "attack"

        details = []
        # Show the command line, unless it is only the program's own path.
        command = p.get("CommandLine", "").strip()
        if command.strip('"').lower() != image.lower():
            details.append(command[:160])
        if p.get("IntegrityLevel") in ("High", "System"):
            details.append("admin rights")
        if kind == "malicious" and image.lower() in dropped_by:
            details.append(f"file dropped by {dropped_by[image.lower()]}")

        return {"depth": depth, "kind": kind, "prefix": prefix, "label": display_name(image),
                "time": clock(p), "detail": " · ".join(details),
                "step": tactic_of_event.get(p["record_id"], "") or tactic_of_process.get(guid, "")}

    def branches(guid):
        """What hangs under a process, in order: first its actions, then its child processes."""
        items = [("action", text, e) for text, e in actions.get(guid, [])]
        items += [("process", child, None) for child in children.get(guid, [])]
        return items

    def add_branches(items, lead, depth):
        """Add a list of items under one parent. `lead` is the tree lines inherited from the
        parents (e.g. "│   "). The last item gets "└── ", the others "├── ". Below a last item
        the line stops ("    "); below the others it continues ("│   ")."""
        for number, (kind, value, e) in enumerate(items):
            if len(rows) >= MAX_TREE_LINES:
                return
            is_last = number == len(items) - 1
            connector = "└── " if is_last else "├── "
            if kind == "action":
                rows.append(action_row(value, e, lead + connector, depth))
            else:
                rows.append(process_row(value, lead + connector, depth))
                next_lead = lead + ("    " if is_last else "│   ")
                # The function calls itself for this process's own items, one level deeper.
                add_branches(branches(value), next_lead, depth + 1)

    # The top line is the computer. Under it: the normal programs (e.g. explorer.exe) whose
    # children are the attack's first processes, then everything below them.
    tops = []
    for guid, p in processes.items():
        parent = p.get("ParentProcessGuid")
        if guid in attack and parent not in attack and parent not in tops:
            tops.append(parent)

    rows.append({"depth": 0, "kind": "computer", "prefix": "", "label": computer_line(events),
                 "time": "", "detail": "", "step": ""})
    add_branches([("process", parent, None) for parent in tops], "", 1)
    return rows
