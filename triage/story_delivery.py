"""How the attack got in: the attack's programs, the browser download record
(Zone.Identifier), and the first step(s) of the story."""

from triage.checks_common import BROWSERS, FILE_IN_TEXT, file_name, is_windows_program
from triage.display import display_name
from triage.parse import to_datetime
from triage.timeline import event_label


BROWSER_NAMES = {"msedge.exe": "Edge", "chrome.exe": "Chrome", "firefox.exe": "Firefox",
                 "brave.exe": "Brave", "opera.exe": "Opera", "iexplore.exe": "Internet Explorer"}


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


def make_step(time, tactic, technique, text, technical, event_ids, guid, image, kind):
    """One how-it-got-in step as a dict (these steps have no confidence: they are reconstructed facts)."""
    return {"time": time, "tactic": tactic, "technique": technique, "text": text, "technical": technical,
            "event_ids": event_ids, "guid": guid, "image": image, "confidence": "", "kind": kind}


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
        steps.append(make_step(origin["event"]["time"], "Initial Access", "", text + ".",
                               f"{event_label(15)} · Zone.Identifier of {delivered}",
                               [origin["event"]["record_id"]], "", lower, "origin"))
    elif "content.outlook" in lower or opener_parent in ("outlook.exe", "olk.exe"):
        steps.append(make_step(opener["time"], "Initial Access", "T1566.001 Spearphishing Attachment",
                               f"{name} was opened from an email attachment.", delivered,
                               [opener["record_id"]], "", lower, "origin"))
    elif len(lower) > 1 and lower[1] == ":" and not lower.startswith("c:"):
        # No technique: the log cannot tell a USB stick from a network drive.
        steps.append(make_step(opener["time"], "Initial Access", "",
                               f"{name} was started from drive {delivered[:2].upper()} "
                               "(possibly a USB or network drive).", delivered,
                               [opener["record_id"]], "", lower, "origin"))
    else:
        steps.append(make_step(opener["time"], "Initial Access", "",
                               f"Where {name} came from is not in this log (no download record).", delivered,
                               [opener["record_id"]], "", lower, "origin"))

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
    steps.append(make_step(opener["time"], "Execution", "T1204.002 User Execution: Malicious File", how + ".",
                           f"{event_label(1)} · {opener.get('CommandLine', '')[:160]} · "
                           f"integrity {opener.get('IntegrityLevel', '?')}",
                           proof, opener.get("ProcessGuid", ""), opener.get("Image", "").lower(), "execution"))
    return steps
