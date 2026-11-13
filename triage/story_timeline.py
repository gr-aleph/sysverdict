"""The Timeline tab: one plain-English row per incident event (what each program did)."""

import re

from triage.checks_common import BROWSERS, PASS_ON_SHELLS, file_name
from triage.display import display_name
from triage.story_delivery import BROWSER_NAMES
from triage.timeline import event_label, in_zone, time_column


# What common discovery tools tell an attacker.
TOOL_PURPOSE = {"whoami.exe": "shows the logged-on user", "ipconfig.exe": "shows the network settings",
                "systeminfo.exe": "shows the computer's details", "net.exe": "lists users, groups or shares",
                "net1.exe": "lists users, groups or shares", "nltest.exe": "finds the domain controllers",
                "quser.exe": "lists logged-on users", "hostname.exe": "shows the computer name",
                "tasklist.exe": "lists running programs", "arp.exe": "lists nearby computers",
                "netstat.exe": "lists network connections", "route.exe": "shows the network routes",
                "nslookup.exe": "looks up names"}


def narrate(e, processes, process_images):
    """One sentence that tells what this event means in the story, with light technical detail.
    processes: process-create events by ProcessGuid; process_images: every started program path (lowercase)."""
    event_id = e["event_id"]
    program = display_name(e.get("Image") or e.get("SourceImage")) or "A program"
    if event_id == 1:
        parent = display_name(e.get("ParentImage"))
        name = file_name(e.get("Image"))
        if name == "consent.exe":
            return "Windows showed the admin approval prompt (UAC)."
        if name == "notepad.exe" and '"' in e.get("CommandLine", ""):
            return f"{parent} opened {e['CommandLine'].split(chr(34))[-2]} in Notepad."
        if e.get("IntegrityLevel") in ("High", "System"):
            program += " (with admin rights)"
        if name in TOOL_PURPOSE:
            launcher = parent
            if file_name(parent) in PASS_ON_SHELLS:  # skip the "cmd /c" in between
                launcher = display_name(processes.get(e.get("ParentProcessGuid"), {}).get("ParentImage")) or parent
            return f"{launcher} ran {program}, which {TOOL_PURPOSE[name]}."
        if parent.lower() == "explorer.exe":
            return f"The user started {program} (double-click in Explorer)."
        if file_name(parent) in BROWSERS:
            return f"{program} was opened from {BROWSER_NAMES.get(file_name(parent), parent)}: {e.get('CommandLine', '')[:120]}"
        if name in ("cmd.exe", "powershell.exe", "pwsh.exe"):
            return f"{parent} started {program} to run: {e.get('CommandLine', '')[:140]}"
        return f"{parent or 'A program'} started {program}: {e.get('CommandLine', '')[:140]}"
    if event_id == 3:
        host = e.get("DestinationHostname", "")
        host = f" ({host})" if host and host != "-" else ""
        return f"{program} connected to {e.get('DestinationIp')}:{e.get('DestinationPort')}{host}."
    if event_id == 22:
        return f"{program} looked up the domain {e.get('QueryName', '').rstrip('.')}."
    if event_id == 15:
        fields = dict(part.split("=", 1) for part in e.get("Contents", "").split() if "=" in part)
        target = display_name(e.get("TargetFilename", "").replace(":Zone.Identifier", ""))
        if fields.get("HostUrl"):
            return f"{BROWSER_NAMES.get(file_name(program), program)} saved {target}, downloaded from {fields['HostUrl']}."
        return f"{program} marked {target} as downloaded from the internet."
    if event_id == 11:
        target = e.get("TargetFilename", "")
        if target.lower() in process_images:
            return f"{program} dropped {target}, which runs later in the attack."
        return f"{program} created the file {target}."
    if event_id in (12, 13, 14):
        target, value = e.get("TargetObject", ""), e.get("Details", "")
        # A Run or RunOnce registry key (same pattern as the persistence check in checks_persistence.py).
        if re.search(r"\\currentversion\\run(once)?\\", target, re.IGNORECASE):
            return f"{program} added the Run key '{target.split(chr(92))[-1]}' so {value[:120]} starts at every logon."
        if target.lower().endswith("\\imagepath"):
            return f"A Windows service '{target.split(chr(92))[-2]}' was set to run {value[:120]}."
        return f"{program} changed the registry: {target[-120:]} = {value[:80]}."
    if event_id == 10:
        return f"{program} opened the memory of {display_name(e.get('TargetImage'))} (access {e.get('GrantedAccess', '?')})."
    if event_id == 8:
        return f"{program} started a thread inside {display_name(e.get('TargetImage'))}."
    if event_id == 5:
        return f"{program} stopped."
    return f"{program}: {event_label(event_id)}."


def attack_tag(step):
    """'Execution · T1204.002 User Execution: Malicious File' (only the tactic if there is no technique)."""
    if step["technique"]:
        return f"{step['tactic']} · {step['technique']}"
    return step["tactic"]


def story_rows(events, steps, zone_name=None):
    """Timeline table rows: Time, Sysmon Event ID, MITRE ATT&CK, Event (one story sentence), Event #.

    MITRE ATT&CK is the tactic and technique of the story step the event belongs to
    ("Execution · T1204.002 User Execution: Malicious File").

    Only the events that lead to the incident are listed: the events behind the story steps.
    """
    processes = {e["ProcessGuid"]: e for e in events if e["event_id"] == 1 and e.get("ProcessGuid")}
    # Every started program, built once here (narrate() checks dropped files against it).
    process_images = set()
    for p in processes.values():
        process_images.add(p.get("Image", "").lower())
    step_of = {}
    for s in steps:
        for event_id in s["event_ids"]:
            step_of.setdefault(event_id, attack_tag(s))
    # Also show where each attack program came from: the event that dropped its file.
    step_images = {}
    for s in steps:
        if s["image"]:
            step_images.setdefault(s["image"], s)  # the first step of each program
    for e in events:
        target = e.get("TargetFilename", "").lower()
        if e["event_id"] == 11 and target in step_images:
            s = step_images[target]
            step_of.setdefault(e["record_id"], attack_tag(s))
    column = time_column(zone_name)
    rows = []
    for e in events:
        step = step_of.get(e["record_id"], "")
        if not step:
            continue  # not part of the incident
        rows.append({column: in_zone(e["time"], zone_name).strftime("%Y-%m-%d %H:%M:%S"),
                     "Sysmon Event ID": event_label(e["event_id"]),
                     "MITRE ATT&CK": step,
                     "Event": narrate(e, processes, process_images),
                     "Event #": e["record_id"]})
    return rows
