"""The detection checks and the verdict.

Each check is one small function that looks at the events and returns a list of findings.
A finding is a plain dict:

    {"check": "recon_burst",                    # which check fired
     "title": "Reconnaissance commands in a burst",
     "strength": "Strong",                      # "Strong" or "Weak"
     "time": "2023-12-13 10:53:39.908",         # first matching event (UTC)
     "process": "C:\\...\\FireEye.exe",         # the program that did it
     "process_guid": "{...}",                   # used to colour the attack map
     "detail": "ran whoami.exe, ipconfig.exe within 60 seconds",
     "event_ids": [16890, 16893]}               # record IDs of the proof

The verdict comes only from the findings (and optionally enrichment), so the same log
always gives the same answer, and every answer can be traced to its events.
"""

import ipaddress
import re
from pathlib import Path

from triage.parse import to_datetime

DATA_DIR = Path(__file__).parent.parent / "data"


def load_list(file_name):
    """Read a data/*.txt file: one lowercase entry per line, '#' starts a comment."""
    entries = []
    for line in (DATA_DIR / file_name).read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip().lower()
        if line:
            entries.append(line)
    return entries


KNOWN_GOOD_PATHS = load_list("known_good.txt")
BRANDS = load_list("brands.txt")

# Folders a normal user can write to. Programs rarely need to run from here.
USER_FOLDER_MARKERS = ["\\users\\", "\\windows\\temp\\", "\\programdata\\", "\\$recycle.bin\\"]

DOCUMENT_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
                 "msaccess.exe", "mspub.exe", "wordpad.exe", "acrord32.exe", "acrobat.exe",
                 "foxitpdfreader.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
          "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe"}
RECON_TOOLS = {"whoami.exe", "ipconfig.exe", "systeminfo.exe", "net.exe", "net1.exe",
               "nltest.exe", "quser.exe", "hostname.exe", "tasklist.exe", "arp.exe",
               "netstat.exe", "route.exe", "nslookup.exe"}
BROWSERS = {"msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "brave.exe",
            "opera.exe", "msedgewebview2.exe"}
# Real Windows programs that should only ever run from the Windows folder.
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "smss.exe",
                "winlogon.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe",
                "conhost.exe", "rundll32.exe", "explorer.exe"}
SYSTEM_FOLDERS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\winsxs\\",
                  "c:\\windows\\explorer.exe")
# Programs that normally touch LSASS memory, and the folders they must run from to be trusted
# (a copy of MsMpEng.exe in a user folder is not Microsoft Defender).
LSASS_OK = {"svchost.exe", "msmpeng.exe", "wininit.exe", "csrss.exe", "wmiprvse.exe",
            "lsass.exe", "services.exe", "mrt.exe"}
LSASS_OK_FOLDERS = ("c:\\windows\\", "c:\\programdata\\microsoft\\windows defender\\",
                    "c:\\program files\\windows defender\\")
# The access right that lets a program read another program's memory (where passwords are).
PROCESS_VM_READ = 0x0010

# Two-part domain endings: in "shop.example.co.uk" the name is "example", not "co".
TWO_PART_ENDINGS = ("co.uk", "com.sg", "com.au", "co.jp")

# File endings a ransom note uses (a text or web page the victim is meant to open).
NOTE_ENDINGS = (".txt", ".html", ".htm", ".hta", ".url", ".rtf")

# PowerShell command-line patterns used to hide or download code. Each one is a regular
# expression, searched in the lower-case command line. Reading guide:
#   \s = a space   [a-z]* = any letters   + = one or more   {40,} = 40 or more
#   | = "or"       \b = a word edge (so "iex" does not match inside "index")   ? = optional
SUSPICIOUS_POWERSHELL = [
    # "-enc" / "-e" / "-encodedcommand" followed by 40+ base64 characters (hidden script).
    r"\s-e[a-z]*\s+[a-z0-9+/=]{40,}",
    # Decoding base64 text inside the script.
    r"frombase64string",
    # Downloading text or a file from the internet.
    r"downloadstring|downloadfile|downloaddata",
    # Other download methods: Invoke-WebRequest (alias iwr), the WebClient class, BITS.
    r"invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer",
    # Running text as code: Invoke-Expression (alias iex).
    r"\biex\b|invoke-expression",
]
# A hidden window alone is not on this list: management agents and scheduled scripts use it too.

# A file name with a fake document ending before a program ending, e.g. "invoice.pdf.exe".
# Part 1 is the fake ending (docx? = doc or docx, jpe?g = jpg or jpeg); part 2 is the real
# program ending; $ means it must be the end of the name.
DOUBLE_EXTENSION = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp3|mp4|avi|mov|mkv|zip|rar)"
    r"\.(exe|scr|com|bat|cmd|vbs|js|pif)$")

# Words typical of ransom-note file names, e.g. "RANSOM.txt", "how_to_recover.html",
# "restore-files.txt". [_ -]? allows an optional underscore, space or dash between words.
RANSOM_NOTE = re.compile(r"ransom|decrypt|how[_ -]?to[_ -]?(recover|restore)|restore[_ -]?files")


# ---------- small helpers ----------

def file_name(path):
    """'C:\\Windows\\System32\\cmd.exe' -> 'cmd.exe' (always lowercase)."""
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def is_known_good(path):
    path = (path or "").lower()
    return any(fragment in path for fragment in KNOWN_GOOD_PATHS)


def in_user_folder(path):
    """True for programs in Downloads, Temp, AppData, ... unless on the known-good list."""
    path = (path or "").lower()
    return any(marker in path for marker in USER_FOLDER_MARKERS) and not is_known_good(path)


def is_public_ip(text):
    try:
        return ipaddress.ip_address(text).is_global
    except ValueError:
        return False


def is_windows_program(path):
    """True for programs in the Windows folder (cmd.exe, powershell.exe, svchost.exe...)."""
    return (path or "").lower().startswith("c:\\windows\\")


def reads_memory(granted_access):
    """True if the access rights (hex text such as "0x1010") include PROCESS_VM_READ.
    An unknown or broken value counts as True: unknown access to LSASS is worth a look."""
    try:
        return (int(granted_access, 16) & PROCESS_VM_READ) != 0
    except (TypeError, ValueError):
        return True


def main_label(domain):
    """The name part of a domain: 'cloud.google.com' -> 'google', 'shop.example.co.uk' -> 'example'.
    A one-part name such as 'wpad' has no name part, so it returns ''."""
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_ENDINGS:
        return labels[-3]
    if len(labels) >= 2:
        return labels[-2]
    return ""


def lookalike_brand(label):
    """The brand this label imitates by one letter ('fireeyee' -> 'fireeye'), or None.
    Short brands (under 5 letters) are skipped: too many normal words are one letter away."""
    for brand in BRANDS:
        if len(brand) >= 5 and edit_distance(label, brand) == 1:
            return brand
    return None


def edit_distance(a, b):
    """How many single-letter changes turn a into b (Levenshtein distance)."""
    previous = list(range(len(b) + 1))
    for i, letter_a in enumerate(a, start=1):
        current = [i]
        for j, letter_b in enumerate(b, start=1):
            current.append(min(previous[j] + 1,                          # delete
                               current[j - 1] + 1,                       # insert
                               previous[j - 1] + (letter_a != letter_b)))  # replace
        previous = current
    return previous[-1]


def add_finding(found, key, event, check, title, strength, process, detail, guid=""):
    """Add an event to a finding. Events with the same key are grouped into one finding.
    A Strong event makes a Weak finding Strong, and its detail and program replace the Weak ones
    (e.g. a malware lookup of a lookalike domain after a browser lookup of it)."""
    if key not in found:
        found[key] = {"check": check, "title": title, "strength": strength,
                      "time": event["time"], "process": process, "process_guid": guid,
                      "detail": detail, "event_ids": []}
    elif strength == "Strong" and found[key]["strength"] == "Weak":
        found[key].update({"strength": "Strong", "process": process, "process_guid": guid,
                           "detail": detail})
    found[key]["event_ids"].append(event["record_id"])


def events_of(events, event_id):
    return [e for e in events if e["event_id"] == event_id]


# ---------- the 10 checks ----------

def check_document_app_spawns_program(events, context):
    """Strong: Word, Excel, WordPad, a PDF reader... starts a shell or a program from a user folder."""
    found = {}
    for e in events_of(events, 1):
        if file_name(e.get("ParentImage")) not in DOCUMENT_APPS:
            continue
        child = e.get("Image", "")
        if file_name(child) in SHELLS or in_user_folder(child):
            add_finding(found, child.lower(), e, "document_app_spawns_program",
                        "Document app started a program", "Strong", child,
                        f"{file_name(e.get('ParentImage'))} started {file_name(child)}",
                        e.get("ProcessGuid", ""))
    return list(found.values())


def check_suspicious_powershell(events, context):
    """Strong: PowerShell with encoded commands, downloads or running text as code."""
    found = {}
    for e in events_of(events, 1):
        if file_name(e.get("Image")) not in ("powershell.exe", "pwsh.exe"):
            continue
        command = e.get("CommandLine", "").lower()
        hits = [p for p in SUSPICIOUS_POWERSHELL if re.search(p, command)]
        if hits:
            add_finding(found, e.get("ProcessGuid"), e, "suspicious_powershell",
                        "Encoded or downloading PowerShell", "Strong", e.get("Image", ""),
                        "command line: " + e.get("CommandLine", "")[:200], e.get("ProcessGuid", ""))
    return list(found.values())


def check_lsass_access(events, context):
    """Strong: a program opened LSASS, the process that holds Windows passwords, with the right
    to read its memory (Event 10)."""
    found = {}
    for e in events_of(events, 10):
        if not e.get("TargetImage", "").lower().endswith("\\lsass.exe"):
            continue
        if not reads_memory(e.get("GrantedAccess")):
            continue  # e.g. Task Manager asking only for basic information (0x1000)
        source = e.get("SourceImage", "")
        trusted_name = file_name(source) in LSASS_OK
        trusted_folder = source.lower().startswith(LSASS_OK_FOLDERS)
        if trusted_name and trusted_folder:
            continue
        add_finding(found, source.lower(), e, "lsass_access", "Credential access (LSASS)",
                    "Strong", source, f"{file_name(source)} opened lsass.exe "
                    f"(access {e.get('GrantedAccess', '?')})", e.get("SourceProcessGUID", ""))
    return list(found.values())


def find_launcher(event, processes):
    """Who really started this command? Skip over a 'cmd /c' or PowerShell in between."""
    guid, image = event.get("ParentProcessGuid", ""), event.get("ParentImage", "")
    if file_name(image) in ("cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe"):
        parent = processes.get(guid)
        if parent:
            guid, image = parent.get("ParentProcessGuid", ""), parent.get("ParentImage", "")
    return guid, image


def check_recon_burst(events, context):
    """Strong: one program runs 2+ different discovery tools (whoami, ipconfig, ...) within 60 s."""
    by_launcher = {}
    for e in events_of(events, 1):
        if file_name(e.get("Image")) in RECON_TOOLS:
            guid, image = find_launcher(e, context["processes"])
            if file_name(image) == "explorer.exe":
                continue  # a person typing in a command window, not a program
            by_launcher.setdefault((guid, image), []).append(e)

    found = {}
    for (guid, image), runs in by_launcher.items():
        for first in runs:
            start = to_datetime(first["time"])
            window = [r for r in runs if 0 <= (to_datetime(r["time"]) - start).total_seconds() <= 60]
            tools = sorted({file_name(r.get("Image")) for r in window})
            if len(tools) >= 2:
                for r in window:
                    if guid in found and r["record_id"] in found[guid]["event_ids"]:
                        continue
                    add_finding(found, guid, r, "recon_burst", "Reconnaissance commands in a burst",
                                "Strong", image, f"{file_name(image)} ran {', '.join(tools)} "
                                "within 60 seconds", guid)
    return list(found.values())


def check_masquerading(events, context):
    """Strong: 'video.mp4.exe' style names, or a Windows program name in the wrong folder."""
    found = {}
    for e in events_of(events, 1) + events_of(events, 11):
        path = e.get("Image", "") if e["event_id"] == 1 else e.get("TargetFilename", "")
        name = file_name(path)
        if DOUBLE_EXTENSION.search(name):
            detail = f"{name} hides its real type behind a double extension"
        elif (e["event_id"] == 1 and name in SYSTEM_NAMES
              and not path.lower().startswith(SYSTEM_FOLDERS)):
            detail = f"{name} is a Windows program name, but runs from {path}"
        else:
            continue
        add_finding(found, path.lower(), e, "masquerading", "Disguised program", "Strong", path,
                    detail, e.get("ProcessGuid", ""))
    return list(found.values())


def check_lookalike_domain(events, context):
    """Strong (Weak from a browser): a DNS lookup whose name part is one letter away from a
    known brand. Only the name part is compared, so 'cloud.google.com' is not read as 'icloud'."""
    found = {}
    for e in events_of(events, 22):
        domain = e.get("QueryName", "").lower().rstrip(".")
        brand = lookalike_brand(main_label(domain))
        if brand is None:
            continue
        from_browser = file_name(e.get("Image")) in BROWSERS
        strength = "Weak" if from_browser else "Strong"
        note = " (from a browser: could be a typing mistake)" if from_browser else ""
        add_finding(found, domain, e, "lookalike_domain", "Lookalike domain", strength,
                    e.get("Image", ""), f"{domain} looks like '{brand}'{note}",
                    e.get("ProcessGuid", ""))
    return list(found.values())


def check_persistence(events, context):
    """Strong: a Run key or new service that starts a file from a user folder, or a service
    whose program was dropped during this log outside Program Files."""
    found = {}
    for e in events_of(events, 13):
        target = e.get("TargetObject", "")
        value = e.get("Details", "")
        writer = e.get("Image", "")
        # The program the key will start, without quotes and arguments.
        value_path = value.strip('"').split('"')[0].lower()
        value_path = value_path.split(".exe")[0] + ".exe" if ".exe" in value_path else value_path

        # A Run or RunOnce registry key, e.g. ...\Microsoft\Windows\CurrentVersion\Run\FireEye.
        # (\\ is one backslash; (once)? means "Once" may follow "Run".)
        if re.search(r"\\currentversion\\run(once)?\\", target, re.IGNORECASE):
            if in_user_folder(writer) or in_user_folder(value_path):
                add_finding(found, target.lower(), e, "persistence", "Starts itself at logon (Run key)",
                            "Strong", writer, f"{file_name(writer)} set {target.split(chr(92))[-1]} "
                            f"= {value[:150]}", e.get("ProcessGuid", ""))
        # The program path of a Windows service: ...\Services\<service name>\ImagePath.
        # ([^\\]+ is the service name: one or more characters that are not a backslash.)
        elif re.search(r"\\services\\[^\\]+\\imagepath$", target, re.IGNORECASE):
            # Real installers put service programs in Program Files; malware often uses
            # System32 or a user folder.
            dropped = value_path in context["dropped_files"]
            in_program_files = "\\program files" in value_path
            if (dropped and not in_program_files) or in_user_folder(value_path):
                service = target.split("\\")[-2]
                # Point at the service program itself (not services.exe, which wrote the key).
                guid = next((p["ProcessGuid"] for p in context["processes"].values()
                             if p.get("Image", "").lower() == value_path), "")
                add_finding(found, target.lower(), e, "persistence", "New service from a dropped file",
                            "Strong", value_path, f"service '{service}' runs {value[:150]}, a file "
                            "created during this log", guid)
    return list(found.values())


def check_ransom_note(events, context):
    """Strong: a text or web file whose name looks like a ransom note, created (Event 11) or
    opened from a command line (Event 1). Other files, such as decrypt_test.py, are ignored."""
    found = {}
    for e in events_of(events, 11) + events_of(events, 1):
        text = e.get("TargetFilename", "") if e["event_id"] == 11 else e.get("CommandLine", "")
        if e["event_id"] == 11:
            names = [file_name(text)]
        else:
            names = [file_name(part.strip('"')) for part in text.split()]
        is_note = False
        for name in names:
            if name.endswith(NOTE_ENDINGS) and RANSOM_NOTE.search(name):
                is_note = True
        if is_note:
            if e["event_id"] == 11:   # the program that wrote the note
                actor, guid = e.get("Image", ""), e.get("ProcessGuid", "")
            else:                     # the program that opened the note (e.g. in Notepad)
                actor, guid = e.get("ParentImage", ""), e.get("ParentProcessGuid", "")
            add_finding(found, "ransom", e, "ransom_note", "Possible ransom note", "Strong",
                        actor, f"{file_name(actor)}: {text[:200]}", guid)
    return list(found.values())


def check_run_from_user_folder(events, context):
    """Weak: a program ran from Downloads, Temp or another user-writable folder."""
    found = {}
    for e in events_of(events, 1):
        image = e.get("Image", "")
        if in_user_folder(image):
            add_finding(found, image.lower(), e, "run_from_user_folder",
                        "Program ran from a user folder", "Weak", image,
                        f"{file_name(image)} ran from {image.rsplit(chr(92), 1)[0]}",
                        e.get("ProcessGuid", ""))
    return list(found.values())


def check_network_from_user_folder(events, context):
    """Weak: a program in a user folder connected to a public IP address."""
    found = {}
    for e in events_of(events, 3):
        image, ip = e.get("Image", ""), e.get("DestinationIp", "")
        if in_user_folder(image) and is_public_ip(ip):
            add_finding(found, (image.lower(), ip), e, "network_from_user_folder",
                        "User-folder program went online", "Weak", image,
                        f"{file_name(image)} connected to {ip}:{e.get('DestinationPort', '')}",
                        e.get("ProcessGuid", ""))
    return list(found.values())


ALL_CHECKS = [
    check_document_app_spawns_program,
    check_suspicious_powershell,
    check_lsass_access,
    check_recon_burst,
    check_masquerading,
    check_lookalike_domain,
    check_persistence,
    check_ransom_note,
    check_run_from_user_folder,
    check_network_from_user_folder,
]


def run_checks(events):
    """Run every check and return all findings, oldest first."""
    context = {
        # ProcessGuid -> its process-creation event, to look up parents.
        "processes": {e["ProcessGuid"]: e for e in events_of(events, 1) if e.get("ProcessGuid")},
        # Every file created during the log (lowercase paths).
        "dropped_files": {e.get("TargetFilename", "").lower() for e in events_of(events, 11)},
    }
    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(events, context))
    findings.sort(key=lambda f: f["time"])
    return findings


def make_verdict(findings, enrichment_verdicts=()):
    """Malicious / Suspicious / Benign, with one sentence saying why.

    enrichment_verdicts is a list of "malicious" / "suspicious" / other words from the backends.
    """
    strong = [f for f in findings if f["strength"] == "Strong"]
    weak = [f for f in findings if f["strength"] == "Weak"]
    enrichment_verdicts = [v.lower() for v in enrichment_verdicts]

    if strong:
        names = sorted({f["title"] for f in strong})
        return {"label": "Malicious", "reason": f"{len(strong)} high-confidence finding(s): " + "; ".join(names)}
    if "malicious" in enrichment_verdicts:
        return {"label": "Malicious", "reason": "an enrichment source rates an indicator as malicious"}
    if weak:
        return {"label": "Suspicious", "reason": f"{len(weak)} low-confidence finding(s) worth a look, "
                                                 "none high-confidence on its own"}
    if "suspicious" in enrichment_verdicts:
        return {"label": "Suspicious", "reason": "an enrichment source rates an indicator as suspicious"}
    return {"label": "Benign", "reason": "no known-bad activity found by any check"}
