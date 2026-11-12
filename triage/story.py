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
  2. one step per finding that belongs to the attack (High, and Low ones of the same programs)
  3. sort them by time and number them 1, 2, 3, ...
"""

import re

from triage.checks import BROWSERS, file_name, is_windows_program
from triage.iocs import FILE_IN_TEXT
from triage.parse import to_datetime
from triage.timeline import event_label, in_zone, time_column

CONFIDENCE = {"Strong": "High", "Weak": "Low"}
BROWSER_NAMES = {"msedge.exe": "Edge", "chrome.exe": "Chrome", "firefox.exe": "Firefox",
                 "brave.exe": "Brave", "opera.exe": "Opera", "iexplore.exe": "Internet Explorer"}


FILE_ENDINGS = {"exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs", "js", "msi", "lnk", "rtf",
                "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar", "mp4", "tmp",
                "dat", "log", "ini", "json", "csv", "png", "jpg", "evtx"}
# A domain (ending in a 2-6 letter top-level domain such as .com or .sg) or an IPv4 address.
# Two patterns joined by | ("or"):
#   domain: (?:[a-z0-9-]+\.)+ = one or more name parts that each end in a dot ("www.", "example."),
#           then [a-z]{2,6} = an ending of 2-6 letters ("com"). \b = a word edge.
#   IPv4:   \d{1,3} = 1-3 digits, then (?:\.\d{1,3}){3} = three more ".digits" groups,
#           then (?::\d{1,5})? = an optional port such as ":80".
DOMAIN_OR_IP = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,6}\b|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b",
                          re.IGNORECASE)


# A full URL, a domain or an IPv4 address (a URL is matched whole, before its domain).
# URL: "http" or "https", "://", then the shortest run of characters that are not spaces,
# quotes or angle brackets (+?), stopping where an optional final punctuation mark
# (. , ; : ) ]) is followed by a space or the end of the text. So in "visit https://a.com/x."
# the URL is "https://a.com/x" without the sentence's full stop.
URL = r"https?://[^\s<>\"'`]+?(?=[.,;:)\]]?(?:\s|$))"
ADDRESS = re.compile(f"{URL}|{DOMAIN_OR_IP.pattern}", re.IGNORECASE)


def code_addresses(text):
    """Wrap URLs, domains and IPs in <code> tags for the page: shown exactly as in the log,
    but never turned into a clickable link. File names are left alone.
    HTML tags (not Markdown backticks) work both in Markdown text and inside HTML blocks
    such as the Findings cards, where Markdown is not processed."""
    def wrap(match):
        token = match.group(0)
        is_url = token.lower().startswith("http")
        if not is_url and token.rsplit(".", 1)[-1].lower() in FILE_ENDINGS:
            return token
        return f"<code>{token}</code>"
    return ADDRESS.sub(wrap, text)


def display_name(path):
    """File name as written in the log (keeps its capitals): 'C:\\x\\FireEye.exe' -> 'FireEye.exe'."""
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1]

# MITRE ATT&CK tag per check: (tactic, technique).
ATTACK_TAGS = {
    "document_app_spawns_program": ("Execution", "T1204.002 User Execution: Malicious File"),
    "suspicious_powershell": ("Execution", "T1059.001 PowerShell"),
    "lsass_access": ("Credential Access", "T1003.001 LSASS Memory"),
    "recon_burst": ("Discovery", "T1033 System Owner/User Discovery"),
    "masquerading": ("Defense Evasion", "T1036 Masquerading"),
    "lookalike_domain": ("Command and Control", "T1071.001 Web Protocols"),
    "persistence_run_key": ("Persistence", "T1547.001 Registry Run Keys"),
    "persistence_service": ("Persistence", "T1543.003 Windows Service"),
    "ransom_note": ("Impact", "T1486 Data Encrypted for Impact"),
    "run_from_user_folder": ("Execution", "T1204.002 User Execution: Malicious File"),
    "network_from_user_folder": ("Command and Control", "T1071.001 Web Protocols"),
}

# A recon burst is tagged by the discovery tool that ran first (other tools: T1033 above).
RECON_TECHNIQUES = {
    "whoami.exe": "T1033 System Owner/User Discovery",
    "quser.exe": "T1033 System Owner/User Discovery",
    "ipconfig.exe": "T1016 System Network Configuration Discovery",
    "route.exe": "T1016 System Network Configuration Discovery",
    "arp.exe": "T1016 System Network Configuration Discovery",
    "nslookup.exe": "T1016 System Network Configuration Discovery",
    "netstat.exe": "T1049 System Network Connections Discovery",
    "systeminfo.exe": "T1082 System Information Discovery",
    "hostname.exe": "T1082 System Information Discovery",
    "net.exe": "T1087 Account Discovery",
    "net1.exe": "T1087 Account Discovery",
    "nltest.exe": "T1087 Account Discovery",
    "tasklist.exe": "T1057 Process Discovery",
}

# One plain sentence per check. {detail} and {process} come from the finding.
SENTENCES = {
    "document_app_spawns_program": "A document program started another program ({detail}). Documents "
                                   "should not start programs: this is how a malicious document runs its payload.",
    "suspicious_powershell": "PowerShell ran encoded commands, downloaded code or ran text as code.",
    "lsass_access": "{detail}. LSASS holds Windows passwords, so this is a sign of credential theft.",
    "recon_burst": "{detail}: discovery commands that malware runs to learn who the user is and what "
                   "the network looks like.",
    "masquerading": "A disguised program appeared: {detail}.",
    "lookalike_domain": "{process} looked up a lookalike domain: {detail}.",
    "persistence_run_key": "{process} added itself to the Run key, so it starts again at every logon.",
    "persistence_service": "A Windows service was created that runs a file dropped during the attack "
                           "({detail}), so it starts again at every boot, with full rights.",
    "ransom_note": "A possible ransom note was opened ({detail}). Treat this as a ransomware incident.",
    "run_from_user_folder": "{detail}.",
    "network_from_user_folder": "{detail}, a server on the internet (possible command and control).",
}

PHASES = ["Investigate", "Contain", "Eradicate", "Recover"]  # NIST SP 800-61 incident response


# ---------- which findings belong to the attack ----------

def attack_processes(events, findings):
    """ProcessGuids and image paths of the High-confidence programs and everything they started."""
    processes = {e["ProcessGuid"]: e for e in events if e["event_id"] == 1 and e.get("ProcessGuid")}
    strong = [f for f in findings if f["strength"] == "Strong"] or findings
    guids = {f["process_guid"] for f in strong if f["process_guid"]}
    # Every run of the same malicious program counts (not Windows' own programs such as
    # powershell.exe, which also run for normal reasons), and so does everything it started.
    images = {f["process"].lower() for f in strong if f["process"] and not is_windows_program(f["process"])}
    guids |= {g for g, p in processes.items() if p.get("Image", "").lower() in images}
    changed = True
    while changed:
        changed = False
        for guid, p in processes.items():
            if guid not in guids and p.get("ParentProcessGuid") in guids:
                guids.add(guid)
                changed = True
    images |= {processes[g].get("Image", "").lower() for g in guids if g in processes}
    return guids, images


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


# ---------- how the attack got in ----------

def zone_identifier(events, path):
    """The browser's download record (Event 15) for a file: {"host_url", "referrer", "browser", "event"}."""
    best = None
    for e in events:
        if e["event_id"] != 15:
            continue
        target = e.get("TargetFilename", "").lower().replace(":zone.identifier", "")
        contents = e.get("Contents", "")
        if target == path.lower() and "ZoneId" in contents:
            if best is None or len(contents) > len(best.get("Contents", "")):
                best = e
    if best is None:
        return None
    fields = dict(part.split("=", 1) for part in best["Contents"].split() if "=" in part)
    return {"host_url": fields.get("HostUrl", ""), "referrer": fields.get("ReferrerUrl", ""),
            "browser": file_name(best.get("Image")), "event": best}


def first_attack_process(events, findings):
    """The earliest process-create event of the attack (the first malicious program that ran)."""
    guids, _ = attack_processes(events, findings)
    starts = [e for e in events if e["event_id"] == 1 and e.get("ProcessGuid") in guids]
    return min(starts, key=lambda e: e["time"]) if starts else None


def find_delivery(events, findings):
    """Steps that explain how the first malicious file arrived and how it was started."""
    root = first_attack_process(events, findings)
    if root is None:
        return []
    processes = {e["ProcessGuid"]: e for e in events if e["event_id"] == 1 and e.get("ProcessGuid")}
    parent = processes.get(root.get("ParentProcessGuid"), {})
    parent_name = file_name(root.get("ParentImage"))

    # If a document program started the malware, the document is what was delivered.
    delivered, opener = root.get("Image", ""), root
    if parent_name in {"winword.exe", "excel.exe", "powerpnt.exe", "wordpad.exe", "acrord32.exe",
                       "acrobat.exe", "onenote.exe", "foxitpdfreader.exe"} and parent:
        # The document is the last file path in the document program's command line, e.g.
        # WINWORD.EXE /n "C:\...\invoice.docm" /o "" -> invoice.docm. Program paths are skipped.
        documents = []
        for path in FILE_IN_TEXT.findall(parent.get("CommandLine", "")):
            if not path.lower().endswith(".exe"):
                documents.append(path)
        if documents:
            delivered, opener = documents[-1], parent
    opener_parent = file_name(opener.get("ParentImage"))
    name = display_name(delivered)
    steps = []

    # 1. Where the file came from.
    origin = zone_identifier(events, delivered)
    lower = delivered.lower()
    if origin and origin["host_url"]:
        browser = BROWSER_NAMES.get(origin["browser"], origin["browser"])
        text = f"The user downloaded {name} with {browser} from {origin['host_url']}"
        if origin["referrer"]:
            text += f", from the page {origin['referrer']}"
        site = origin["referrer"] or origin["host_url"]
        host = site.split("://", 1)[-1].split("/", 1)[0]
        looked_up = any(e["event_id"] == 22 and e.get("QueryName", "").rstrip(".").lower() == host.lower()
                        and file_name(e.get("Image")) in BROWSERS for e in events)
        if not looked_up:
            text += (". How the user reached that site (a link, a search, an ad or an email) is not "
                     "in this log")
        # No technique: how the user reached the site (link, search, ad, email) is not in the log,
        # and a referrer page alone does not prove phishing.
        steps.append({"time": origin["event"]["time"], "tactic": "Initial Access", "technique": "",
                      "text": text + ".", "technical": f"{event_label(15)} · Zone.Identifier of {delivered}",
                      "event_ids": [origin["event"]["record_id"]], "guid": "", "image": lower,
                      "confidence": "", "kind": "origin"})
    elif "content.outlook" in lower or opener_parent in ("outlook.exe", "olk.exe"):
        steps.append({"time": opener["time"], "tactic": "Initial Access",
                      "technique": "T1566.001 Spearphishing Attachment",
                      "text": f"{name} was opened from an email attachment.", "technical": delivered,
                      "event_ids": [opener["record_id"]], "guid": "", "image": lower,
                      "confidence": "", "kind": "origin"})
    elif len(lower) > 1 and lower[1] == ":" and not lower.startswith("c:"):
        # No technique: the log cannot tell a USB stick from a network drive.
        steps.append({"time": opener["time"], "tactic": "Initial Access", "technique": "",
                      "text": f"{name} was started from drive {delivered[:2].upper()} "
                              "(possibly a USB or network drive).",
                      "technical": delivered, "event_ids": [opener["record_id"]], "guid": "",
                      "image": lower, "confidence": "", "kind": "origin"})
    else:
        steps.append({"time": opener["time"], "tactic": "Initial Access", "technique": "",
                      "text": f"Where {name} came from is not in this log (no download record).",
                      "technical": delivered, "event_ids": [opener["record_id"]], "guid": "",
                      "image": lower, "confidence": "", "kind": "origin"})

    # 2. Who started it.
    if opener_parent == "explorer.exe":
        how = f"The user opened {name} by double-clicking it"
    elif opener_parent in BROWSERS:
        how = f"The user opened {name} straight from {BROWSER_NAMES.get(opener_parent, opener_parent)}"
    else:
        how = f"{display_name(opener.get('ParentImage')) or 'An unknown program'} started {name}"
    if opener is not root:
        how += f", which opened it in {display_name(opener.get('Image'))}"
    start = to_datetime(opener["time"])
    uac = [e for e in events if e["event_id"] == 1 and file_name(e.get("Image")) == "consent.exe"
           and 0 <= (start - to_datetime(e["time"])).total_seconds() <= 30]
    if uac and root.get("IntegrityLevel") in ("High", "System"):
        how += ", and approved the Windows admin prompt (UAC), so it ran with full rights"
    proof = [opener["record_id"]] + [e["record_id"] for e in uac[-1:]]
    steps.append({"time": opener["time"], "tactic": "Execution",
                  "technique": "T1204.002 User Execution: Malicious File", "text": how + ".",
                  "technical": f"{event_label(1)} · {opener.get('CommandLine', '')[:160]} · "
                               f"integrity {opener.get('IntegrityLevel', '?')}",
                  "event_ids": proof, "guid": opener.get("ProcessGuid", ""),
                  "image": opener.get("Image", "").lower(), "confidence": "", "kind": "execution"})
    return steps


# ---------- the full story ----------

def tag_key(finding):
    if finding["check"] == "persistence":
        return "persistence_service" if "service" in finding["title"].lower() else "persistence_run_key"
    return finding["check"]


def finding_step(f, events_by_id):
    key = tag_key(f)
    tactic, technique = ATTACK_TAGS[key]
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


# ---------- the Timeline table: one story sentence per event ----------

# What common discovery tools tell an attacker.
TOOL_PURPOSE = {"whoami.exe": "shows the logged-on user", "ipconfig.exe": "shows the network settings",
                "systeminfo.exe": "shows the computer's details", "net.exe": "lists users, groups or shares",
                "net1.exe": "lists users, groups or shares", "nltest.exe": "finds the domain controllers",
                "quser.exe": "lists logged-on users", "hostname.exe": "shows the computer name",
                "tasklist.exe": "lists running programs", "arp.exe": "lists nearby computers",
                "netstat.exe": "lists network connections", "route.exe": "shows the network routes",
                "nslookup.exe": "looks up names"}
SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe")


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
            if file_name(parent) in SHELLS:  # skip the "cmd /c" in between
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
        # A Run or RunOnce registry key (same pattern as the persistence check in checks.py).
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


# ---------- next steps, grouped by NIST incident-response phase ----------

ACTIONS = {
    "ransom_note": [("Contain", "Disconnect the computer from the network now; do not shut it down "
                                "(memory holds evidence)."),
                    ("Investigate", "Find which files were encrypted and whether data was copied out first."),
                    ("Eradicate", "Rebuild the computer from a known-good image instead of cleaning it."),
                    ("Recover", "Restore files from offline backups after checking the backups are clean.")],
    "lsass_access": [("Contain", "Reset the passwords of every account that logged on to this computer, "
                                 "admins first."),
                     ("Investigate", "Check where those accounts logged on after the LSASS access.")],
    "recon_burst": [("Contain", "Isolate the computer: the malware ran and probably reported back."),
                    ("Investigate", "Check what the same program did after the discovery commands.")],
    "persistence": [("Eradicate", "Remove the Run key or service listed under IOCs, reboot, and confirm "
                                  "it does not come back."),
                    ("Investigate", "Search other computers for the same Run key or service name.")],
    "document_app_spawns_program": [("Investigate", "Find where the document came from (see IOCs) and "
                                                    "search mailboxes and other computers for it."),
                                    ("Eradicate", "Delete the document and every file it dropped.")],
    "masquerading": [("Investigate", "Collect the disguised file for analysis and search other computers "
                                     "for its SHA256."),
                     ("Eradicate", "Delete the disguised file and all its copies.")],
    "suspicious_powershell": [("Investigate", "Decode the PowerShell command to see what it downloaded or ran.")],
    "lookalike_domain": [("Contain", "Block the lookalike domain at the DNS filter or web proxy."),
                         ("Investigate", "Search DNS and proxy logs for other computers that visited it.")],
    "network_from_user_folder": [("Contain", "Block the attacker IPs listed under IOCs at the firewall.")],
    "run_from_user_folder": [("Investigate", "Ask the user whether they installed the programs listed "
                                             "under Findings.")],
}


def next_steps(findings, verdict, steps=()):
    """Return {"Investigate": [...], "Contain": [...], "Eradicate": [...], "Recover": [...]} (no empty phases)."""
    plan = {phase: [] for phase in PHASES}

    def add(phase, text):
        if text not in plan[phase] and len(plan[phase]) < 4:
            plan[phase].append(text)

    if verdict["label"] == "Benign":
        add("Investigate", "Nothing known-bad was found by the 10 checks; this does not prove the "
                           "computer is clean. Keep this result with the ticket.")
        add("Investigate", "If the user still reports a problem, collect a longer log and run it again.")
    else:
        strong_checks = {f["check"] for f in findings if f["strength"] == "Strong"}
        fired = strong_checks or {f["check"] for f in findings}
        for check, actions in ACTIONS.items():
            if check in fired:
                for phase, text in actions:
                    add(phase, text)
        for step in steps:
            # The host of the download address: the characters after "://" up to the first
            # "/", space, comma, quote or bracket ([^...]+ = one or more characters NOT in the list),
            # so "https://a.com, from the page ..." gives "a.com".
            found = re.search(r"://([^/\s,;'\"()`]+)", step["text"]) if step.get("kind") == "origin" else None
            if found:
                add("Contain", f"Block the download site {found.group(1)} at the web proxy.")
            if step.get("technique", "").startswith("T1566.001"):
                add("Investigate", "Find the email and remove it from every mailbox.")
        if verdict["label"] == "Malicious":
            add("Investigate", "Add the IOCs to the ticket and look for them in your EDR, proxy and email logs.")
            add("Recover", "Return the computer to service only after a clean scan and a day of monitoring.")
        else:
            add("Investigate", "If the user did not expect these programs, treat the computer as compromised.")
    return {phase: items for phase, items in plan.items() if items}
