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

import base64
import ipaddress
import re
from pathlib import Path

from triage.parse import hide_secrets, to_datetime

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
# Programs that mean "a person at the keyboard": the desktop, a remote admin session over
# WinRM (wsmprovhost.exe hosts PowerShell remoting), and the windows people type commands in
# (Windows Terminal, the PowerShell ISE, VS Code's terminal). Recon typed by a person is normal
# help-desk work.
PERSON_PROGRAMS = {"explorer.exe", "wsmprovhost.exe", "windowsterminal.exe", "powershell_ise.exe", "code.exe"}
# Shells that only pass a command on: the recon check looks past them to find who started it.
PASS_ON_SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe")
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
# Only the system folders, not all of C:\Windows (C:\Windows\Temp is writable by everyone).
LSASS_OK_FOLDERS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                    "c:\\programdata\\microsoft\\windows defender\\",
                    "c:\\program files\\windows defender\\")
# The access right that lets a program read another program's memory (where passwords are).
PROCESS_VM_READ = 0x0010

# Two-part domain endings: in "shop.example.co.uk" the name is "example", not "co".
TWO_PART_ENDINGS = ("co.uk", "com.sg", "com.au", "co.jp")

# Domains a brand owns itself, whose name part happens to be one letter from another brand
# (Microsoft 365 moved to *.cloud.microsoft; "cloud" is one letter from "icloud"). A lookup of
# one of these, or of a subdomain, is never a lookalike. Source: Microsoft's own domain list.
BRAND_OWNED_DOMAINS = ("cloud.microsoft",)

# File endings a ransom note uses (a text or web page the victim is meant to open).
NOTE_ENDINGS = (".txt", ".html", ".htm", ".hta", ".url", ".rtf")

# PowerShell is judged by what the command DOES, after decoding an encoded command.
# Encoding alone is not a finding: monitoring agents and admins encode commands too.
# Reading guide for the regular expressions below:
#   \s = a space   [a-z]* = any letters   + = one or more   {20,} = 20 or more
#   | = "or"       \b = a word edge (so "iex" does not match inside "index")   ( ) = the part we keep

# "-enc" / "-e" / "-EncodedCommand" followed by base64 text (the hidden command), e.g.
# "powershell -EncodedCommand aQB3AHIA...". Group 1 is the base64 text.
ENCODED_COMMAND = re.compile(r"\s-e[a-z]*\s+([a-z0-9+/=]{20,})", re.IGNORECASE)
# Downloading text or a file from the internet: the WebClient methods, Invoke-WebRequest
# (aliases iwr, and curl/wget in Windows PowerShell 5), Invoke-RestMethod (alias irm), BITS.
PS_DOWNLOAD = re.compile(r"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|"
                         r"\biwr\b|\bcurl\b|\bwget\b|invoke-restmethod|\birm\b|start-bitstransfer")
# The official one-line installers of the Chocolatey and Scoop package managers download a
# script and run it (documented on chocolatey.org and scoop.sh). Admins paste these every day:
# Low, not High. Only these exact sources; any other download-and-run stays as judged.
OFFICIAL_INSTALLERS = re.compile(r"community\.chocolatey\.org/install\.ps1|get\.scoop\.sh")
# Running text as code: Invoke-Expression (alias iex).
PS_RUN_TEXT = re.compile(r"\biex\b|invoke-expression")
# Turning base64 text back into code inside the script.
PS_DECODE = re.compile(r"frombase64string")
# A hidden window, -ExecutionPolicy Bypass or an encoded command alone is not a finding:
# management agents (Intune, RMM, monitoring) use them all day (measured: up to 30 times in one
# normal log), so they would bury the real signals.

# A file name with a fake document ending before a program ending, e.g. "invoice.pdf.exe".
# Part 1 is the fake ending (docx? = doc or docx, jpe?g = jpg or jpeg); part 2 is the real
# program ending; $ means it must be the end of the name.
DOUBLE_EXTENSION = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp3|mp4|avi|mov|mkv|zip|rar)"
    r"\.(exe|scr|com|bat|cmd|vbs|js|pif)$")

# Words typical of ransom-note file names, e.g. "RANSOM.txt", "how_to_recover.html",
# "restore-files.txt", "RESTORE_MY_FILES.txt". [_ -]? allows an optional underscore, space or
# dash between words. ("readme" is not on the list: every installer writes a readme.txt.)
RANSOM_NOTE = re.compile(r"ransom|decrypt|how[_ -]?to[_ -]?(recover|restore)|restore[_ -]?(my[_ -]?)?files")

# A Windows path such as C:\Users\x\report.pdf inside a command line (it ends at a quote,
# a space or the end of the text, so "video.mp4.exe" is read whole).
# Pieces: [a-z]:\\ = drive letter and backslash; [^\"]+? = the shortest run of characters
# that are not quotes; \.[a-z0-9]{2,4} = a file ending of 2-4 characters; (?=[\"\s]|$) =
# "followed by a quote, a space or the end", without including that character.
# (Also used by iocs.py and story.py.)
FILE_IN_TEXT = re.compile(r"[a-z]:\\[^\"]+?\.[a-z0-9]{2,4}(?=[\"\s]|$)", re.IGNORECASE)


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


def full_windows_path(path):
    """Service paths are often written in short forms; turn them into C:\\Windows\\... (lowercase):
    '%SystemRoot%\\System32\\svchost.exe', '\\SystemRoot\\System32\\drivers\\x.sys',
    'System32\\drivers\\x.sys' and '\\??\\C:\\...' all point into the Windows folder or a full path."""
    path = path.lower().replace("%systemroot%", "c:\\windows").replace("%windir%", "c:\\windows")
    if path.startswith("\\??\\"):
        path = path[4:]
    if path.startswith("\\systemroot\\"):
        path = "c:\\windows\\" + path[len("\\systemroot\\"):]
    if path.startswith("system32\\"):
        path = "c:\\windows\\" + path
    return path


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


# ---------- the checks (each one is listed in ALL_CHECKS at the end) ----------

def check_document_app_spawns_program(events, context):
    """Strong: Word, Excel, WordPad, a PDF reader... starts a shell or a program from a user folder."""
    found = {}
    for e in events_of(events, 1):
        if file_name(e.get("ParentImage")) not in DOCUMENT_APPS:
            continue
        child = e.get("Image", "")
        # A browser (a person clicked a link in the document or e-mail; a per-user Chrome lives in
        # AppData) and Windows' "Open with" dialog (rundll32 shell32.dll,OpenAs_RunDLL) are normal.
        if file_name(child) in BROWSERS:
            continue
        if file_name(child) == "rundll32.exe" and "openas_rundll" in e.get("CommandLine", "").lower():
            continue
        if file_name(child) in SHELLS or in_user_folder(child):
            add_finding(found, child.lower(), e, "document_app_spawns_program",
                        "Document app started a program", "Strong", child,
                        f"{file_name(e.get('ParentImage'))} started {file_name(child)}",
                        e.get("ProcessGuid", ""))
    return list(found.values())


def decode_powershell(command):
    """The hidden command of 'powershell -EncodedCommand <base64>' as readable text, or "".
    PowerShell's base64 holds UTF-16 text (2 bytes per letter)."""
    match = ENCODED_COMMAND.search(command)
    if not match:
        return ""
    text = match.group(1)
    text += "=" * (-len(text) % 4)  # base64 length must be a multiple of 4
    try:
        decoded = base64.b64decode(text).decode("utf-16-le", errors="replace")
    except ValueError:  # not real base64
        return ""
    # The hidden command can contain a password too: hide it before it is checked or shown.
    return hide_secrets(decoded)


def check_suspicious_powershell(events, context):
    """Strong: PowerShell downloads code AND runs it (or runs hidden decoded code).
    Weak: PowerShell only downloads, only runs text as code, or only decodes base64.
    The command is judged after decoding an encoded command; encoding alone is no finding."""
    found = {}
    for e in events_of(events, 1):
        if file_name(e.get("Image")) not in ("powershell.exe", "pwsh.exe"):
            continue
        command = e.get("CommandLine", "")
        decoded = decode_powershell(command)
        everything = (command + " " + decoded).lower()
        downloads = bool(PS_DOWNLOAD.search(everything))
        runs_text = bool(PS_RUN_TEXT.search(everything))
        decodes = bool(PS_DECODE.search(everything))
        if runs_text and (downloads or decodes) and OFFICIAL_INSTALLERS.search(everything):
            strength, title = "Weak", "PowerShell ran a package manager's official installer"
        elif runs_text and (downloads or decodes):
            strength, title = "Strong", "PowerShell downloaded and ran code"
        elif downloads or runs_text or decodes:
            strength, title = "Weak", "PowerShell download or hidden code"
        else:
            continue  # e.g. an encoded command that only reads a CPU counter
        shown = "decoded command: " + decoded if decoded else "command line: " + command
        add_finding(found, e.get("ProcessGuid"), e, "suspicious_powershell", title, strength,
                    e.get("Image", ""), shown[:200], e.get("ProcessGuid", ""))
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
    """Who really started this command? Walk up past every 'cmd /c' or PowerShell in between
    (e.g. agent -> cmd -> powershell -> whoami gives the agent). If a shell's own start is not in
    the log (it was opened before the log began), the shell itself is returned."""
    guid, image = event.get("ParentProcessGuid", ""), event.get("ParentImage", "")
    for _ in range(10):  # 10 shells inside each other is already far more than real life
        if file_name(image) not in PASS_ON_SHELLS:
            break
        parent = processes.get(guid)
        if not parent:
            break  # the shell started before the log: we cannot see who opened it
        guid, image = parent.get("ParentProcessGuid", ""), parent.get("ParentImage", "")
    return guid, image


def check_recon_burst(events, context):
    """Strong: one program runs 2+ different discovery tools (whoami, ipconfig, ...) within 60 s.
    ATT&CK Discovery (T1033, T1016, T1082). Why 60 s and 2 tools: a person pauses to read each
    answer, a script runs its tools within seconds; 60 s is a generous window for that.
    Dual-use: admin and monitoring (RMM) tools run the same commands, so apply_dual_use_gate
    keeps it Strong only when the program has another high-confidence sign."""
    by_launcher = {}
    for e in events_of(events, 1):
        if file_name(e.get("Image")) in RECON_TOOLS:
            guid, image = find_launcher(e, context["processes"])
            if file_name(image) in PERSON_PROGRAMS:
                continue  # a person typing (locally or in a remote admin session), not a program
            if file_name(image) in PASS_ON_SHELLS:
                continue  # a shell opened before the log began: most likely a person's window
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
        if any(domain == owned or domain.endswith("." + owned) for owned in BRAND_OWNED_DOMAINS):
            continue
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
    """Strong: a Run key that starts a user-folder DLL with rundll32/regsvr32, or a service whose
    program is in a user folder or was dropped during this log outside Program Files.
    Weak: a Run key that starts a program from a user folder (tray apps do this too)."""
    found = {}
    for e in events_of(events, 13):
        target = e.get("TargetObject", "")
        value = e.get("Details", "")
        writer = e.get("Image", "")
        # The program the key will start, without quotes and arguments.
        value_path = value.strip('"').split('"')[0].lower()
        value_path = value_path.split(".exe")[0] + ".exe" if ".exe" in value_path else value_path
        value_path = full_windows_path(value_path)

        # A Run or RunOnce registry key, e.g. ...\Microsoft\Windows\CurrentVersion\Run\FireEye.
        # (\\ is one backslash; (once)? means "Once" may follow "Run".)
        if re.search(r"\\currentversion\\run(once)?\\", target, re.IGNORECASE):
            detail = f"{file_name(writer)} set {target.split(chr(92))[-1]} = {value[:150]}"
            # rundll32/regsvr32 starting a DLL from a user folder at every logon: no common
            # legitimate use, so Strong. A program in a user folder: tray apps (Discord, Zoom)
            # do this too, so Weak.
            starts_user_dll = (file_name(value_path) in ("rundll32.exe", "regsvr32.exe")
                               and ".dll" in value.lower() and in_user_folder(value))
            if starts_user_dll:
                add_finding(found, target.lower(), e, "persistence", "Starts a DLL at logon (Run key)",
                            "Strong", writer, detail, e.get("ProcessGuid", ""))
            elif in_user_folder(writer) or in_user_folder(value_path):
                add_finding(found, target.lower(), e, "persistence", "Starts itself at logon (Run key)",
                            "Weak", writer, detail, e.get("ProcessGuid", ""))
            # Any other new Run key entry is worth a look too (ATT&CK T1547.001), except a known-good
            # program, or an installed program adding ITSELF (Edge, Teams and tray apps do this).
            elif not is_known_good(value_path) and file_name(writer) != file_name(value_path):
                add_finding(found, target.lower(), e, "persistence", "New program set to start at logon",
                            "Weak", writer, detail, e.get("ProcessGuid", ""))
        # The program path of a Windows service: ...\Services\<service name>\ImagePath.
        # ([^\\]+ is the service name: one or more characters that are not a backslash.)
        elif re.search(r"\\services\\[^\\]+\\imagepath$", target, re.IGNORECASE):
            # Real installers put service programs in Program Files; malware often uses
            # System32 or a user folder.
            dropped = value_path in context["dropped_files"]
            in_program_files = "\\program files" in value_path
            # Defender platform updates (known-good list) and driver updates (Windows installs
            # drivers from its DriverStore) create new service files all the time.
            if is_known_good(value_path) or "\\windows\\system32\\driverstore\\" in value_path:
                continue
            service = target.split("\\")[-2]
            # Point at the service program itself (not services.exe, which wrote the key).
            guid = next((p["ProcessGuid"] for p in context["processes"].values()
                         if p.get("Image", "").lower() == value_path), "")
            if (dropped and not in_program_files) or in_user_folder(value_path):
                add_finding(found, target.lower(), e, "persistence", SERVICE_TITLE,
                            "Strong", value_path, f"service '{service}' runs {value[:150]}, a file "
                            "created during this log", guid)
            # Any other new or changed service is worth a look too (ATT&CK T1543.003), except one in
            # the Windows folder (Windows updates rewrite those all the time). A service that runs a
            # shell (cmd /c ..., %COMSPEC%, powershell) is the PsExec / attack-tool pattern
            # (T1569.002), so it is reported even though cmd.exe lives in the Windows folder.
            elif (not value_path.startswith("c:\\windows\\") or file_name(value_path) in SHELLS
                  or "%comspec%" in value.lower()):
                add_finding(found, target.lower(), e, "persistence", "New or changed service",
                            "Weak", value_path or value, f"service '{service}' runs {value[:150]}", guid)
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
            # Words of the command line ("notepad RANSOM.txt") and full paths, which may contain
            # spaces ("C:\Users\a\Desktop\HOW TO RECOVER.txt").
            names = [file_name(part.strip('"')) for part in text.split()]
            names += [file_name(path) for path in FILE_IN_TEXT.findall(text)]
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


# Programs that run scripts or other code for someone else (ATT&CK T1059 Command and Scripting
# Interpreter, T1218 System Binary Proxy Execution).
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
                "wscript.exe", "cscript.exe"}


def check_script_host_online(events, context):
    """Weak: a script or proxy host (PowerShell, rundll32, mshta, wscript...) itself connected to a
    public IP: how download cradles and beacons talk to the internet (T1105, T1071).
    Dual-use: admin scripts also download updates, so Low. Connections TO the computer
    (Initiated = false) and to private addresses are not reported."""
    found = {}
    for e in events_of(events, 3):
        image, ip = e.get("Image", ""), e.get("DestinationIp", "")
        outgoing = e.get("Initiated", "true").lower() == "true"
        if file_name(image) in SCRIPT_HOSTS and is_public_ip(ip) and outgoing:
            add_finding(found, (image.lower(), ip), e, "script_host_online", "Script host went online",
                        "Weak", image, f"{file_name(image)} connected to {ip}:{e.get('DestinationPort', '')}",
                        e.get("ProcessGuid", ""))
    return list(found.values())


# Web and database server processes. They serve pages and queries; they do not start shells.
# A web shell (a script an attacker uploaded to the website) makes them do exactly that
# (ATT&CK T1505.003 Web Shell, T1190 Exploit Public-Facing Application; SQL Server's
# xp_cmdshell: T1505.001). Names: IIS (w3wp), Apache (httpd), nginx, PHP, Tomcat, SQL Server,
# Exchange's Unified Messaging worker.
SERVER_PROCESSES = ("w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "tomcat", "sqlservr.exe",
                    "umworkerprocess.exe")


def check_web_shell(events, context):
    """Strong: a web or database server started a shell, a script host or a recon tool.
    Not dual-use: a normal web application does not open a command prompt."""
    found = {}
    for e in events_of(events, 1):
        parent = file_name(e.get("ParentImage"))
        child = e.get("Image", "")
        if not parent.startswith(SERVER_PROCESSES):
            continue
        if file_name(child) in SHELLS | SCRIPT_HOSTS | RECON_TOOLS:
            add_finding(found, (parent, file_name(child)), e, "web_shell", "Server started a shell (web shell)",
                        "Strong", child, f"{parent} started {file_name(child)}: "
                        f"{e.get('CommandLine', '')[:160]}", e.get("ProcessGuid", ""))
    return list(found.values())


# Remote-access and remote-management (RMM) tools, by the start of their program names. Source:
# the LOLRMM project (lolrmm.io) and CISA advisory AA23-025A on RMM tools misused by attackers
# (ATT&CK T1219 Remote Access Software). Dual-use: help desks use them every day, so Low.
REMOTE_ACCESS_TOOLS = ("anydesk", "teamviewer", "screenconnect", "connectwisecontrol", "rustdesk",
                       "splashtop", "srservice", "ateraagent", "ninjarmmagent", "agentmon", "logmein",
                       "rutserv", "rfusclient", "supremo", "meshagent", "action1", "simplehelp",
                       "remotepc", "tightvnc", "tvnserver", "ultravnc", "winvnc")


def check_remote_access_tool(events, context):
    """Weak: a remote-access / RMM tool was installed or ran. One finding per tool."""
    found = {}
    for e in events_of(events, 1):
        name = file_name(e.get("Image"))
        tool = next((t for t in REMOTE_ACCESS_TOOLS if name.startswith(t)), None)
        if tool:
            add_finding(found, tool, e, "remote_access_tool", "Remote-access tool ran", "Weak",
                        e.get("Image", ""), f"{name} ran (a remote-access tool: was a support session "
                        "planned?)", e.get("ProcessGuid", ""))
    return list(found.values())


# ---------- data theft: packing, copying out, uploading ----------

# Packing files into an archive (ATT&CK T1560.001 Archive via Utility; collecting files in one
# place is also T1074.001 Local Data Staging). Dual-use: people zip files every day, so Low.
#   7z/7za/7zr/7zg/rar/winrar with the "a" (add) command: "7z a out.7z C:\docs"
#   tar with a "c" (create) option: "tar -czf out.tgz docs"; Compress-Archive; makecab
#   (?<![\w.])tar = "tar" as a program, not the end of "a.tar"; (?-i:...) = this part is
#   case-sensitive, because tar's -C (capital) means "change folder", not "create".
ARCHIVE_COMMAND = re.compile(r"\b(7z[arg]?|rar|winrar)(\.exe)?\"?\s+a\s|"
                             r"(?<![\w.])tar(\.exe)?\"?\s+-?(?-i:[a-z]*c[a-z]*)\s|"
                             r"compress-archive\b|\bmakecab(\.exe)?\b", re.IGNORECASE)
# The archive file named after "7z a" / "rar a" (options such as -p or -tzip may come first).
ARCHIVE_NAME = re.compile(r"\b(?:7z[arg]?|rar|winrar)(?:\.exe)?\"?\s+a\s+(?:-\S+\s+)*\"?([^\"\s]+)",
                          re.IGNORECASE)
# Endings an archive file really has (.001 = the first part of a split archive).
ARCHIVE_ENDINGS = (".7z", ".zip", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".001")


def check_archive(events, context):
    """Weak: files were packed into an archive (dual-use).
    Strong: the archive got a non-archive ending ("7z a holiday.jpg docs\\"), which disguises it as
    another file type (T1036.008 Masquerade File Type): no common legitimate use."""
    found = {}
    for e in events_of(events, 1):
        command = e.get("CommandLine", "")
        if not ARCHIVE_COMMAND.search(command):
            continue
        name_match = ARCHIVE_NAME.search(command)
        archive = file_name(name_match.group(1)) if name_match else ""
        # 7-Zip and RAR add their own ending to a name without one, so only a different ending counts.
        disguised = "." in archive and not archive.endswith(ARCHIVE_ENDINGS)
        if disguised:
            title, strength = "Archive disguised as another file type", "Strong"
        else:
            title, strength = "Files packed into an archive", "Weak"
        add_finding(found, (file_name(e.get("Image")), title), e, "archive", title, strength,
                    e.get("Image", ""), f"{file_name(e.get('Image'))}: {command[:180]}", e.get("ProcessGuid", ""))
        if disguised:
            found[(file_name(e.get("Image")), title)].update(
                {"tactic": "Defense Evasion", "technique": "T1036.008 Masquerade File Type"})
    return list(found.values())


# A "bulk copy": a person saves a few files to a USB stick; copying a folder writes dozens within
# minutes. 20 files in 10 minutes separates the two (a judgement from how people work, not from
# any log). Exfiltration over USB is ATT&CK T1052.001. Sysmon cannot tell a USB stick from another
# drive, so every drive except C: counts (a network drive is a copy-out too). Dual-use: Low.
BULK_FILES, BULK_SECONDS = 20, 600
OTHER_DRIVE = re.compile(r"^[a-bd-z]:\\", re.IGNORECASE)


def check_copy_to_other_drive(events, context):
    """Weak: 20+ files, or any archive, written to a drive other than C: within 10 minutes."""
    by_drive = {}
    for e in events_of(events, 11):
        path = e.get("TargetFilename", "")
        if OTHER_DRIVE.match(path) and ":zone.identifier" not in path.lower():
            by_drive.setdefault(path[0].upper(), []).append(e)

    found = {}
    for drive, files in by_drive.items():
        files.sort(key=lambda e: e["time"])
        for first in files:
            start = to_datetime(first["time"])
            window = [f for f in files if 0 <= (to_datetime(f["time"]) - start).total_seconds() <= BULK_SECONDS]
            archives = [f for f in window if f.get("TargetFilename", "").lower().endswith(ARCHIVE_ENDINGS)]
            if len(window) >= BULK_FILES or archives:
                proof = window if len(window) >= BULK_FILES else archives
                for f in proof:
                    add_finding(found, drive, f, "copy_to_other_drive", "Files copied to another drive (USB?)",
                                "Weak", f.get("Image", ""), f"{len(window)} file(s) written to drive {drive}: "
                                f"within 10 minutes (archives: {len(archives)})", f.get("ProcessGuid", ""))
                break  # one finding per drive is enough
    return list(found.values())


# File-transfer services and tools that attackers use to upload stolen data (ATT&CK T1567.002
# Exfiltration to Cloud Storage; incident reports most often name MEGA with rclone or MEGAsync,
# and one-off transfer sites). Mainstream storage (Dropbox, Google Drive, OneDrive) is left out:
# nearly every normal computer uses one. Dual-use: Low.
TRANSFER_SITES = ("mega.nz", "mega.co.nz", "mega.io", "wetransfer.com", "we.tl", "file.io", "gofile.io",
                  "transfer.sh", "sendspace.com", "pixeldrain.com", "catbox.moe", "anonfiles.com",
                  "bashupload.com", "temp.sh", "filebin.net", "ufile.io")
TRANSFER_TOOLS = ("rclone", "megasync", "megacmd", "megatools")


def check_cloud_upload(events, context):
    """Weak: a file-transfer site was looked up, or an upload tool such as rclone ran."""
    found = {}
    for e in events_of(events, 22):
        domain = e.get("QueryName", "").lower().rstrip(".")
        site = next((s for s in TRANSFER_SITES if domain == s or domain.endswith("." + s)), None)
        if site:
            add_finding(found, site, e, "cloud_upload", "File-transfer site used", "Weak", e.get("Image", ""),
                        f"{file_name(e.get('Image'))} looked up {domain}", e.get("ProcessGuid", ""))
    for e in events_of(events, 1):
        name = file_name(e.get("Image"))
        if name.startswith(TRANSFER_TOOLS):
            add_finding(found, name, e, "cloud_upload", "Upload tool ran", "Weak", e.get("Image", ""),
                        f"{name}: {e.get('CommandLine', '')[:180]}", e.get("ProcessGuid", ""))
    return list(found.values())


# ---------- command-line checks (one list of patterns per check) ----------
# Each rule is (pattern, what it means, ATT&CK tactic, ATT&CK technique). The patterns are searched
# in a program's command line, ignoring upper/lower case. Reading guide for the patterns:
#   \b = a word edge   \s = a space   \S = not a space   .* = anything   (x)? = x is optional
#   \\\\ = the two backslashes of a network path (\\server)   [a-z0-9._-]+ = a computer name
#   (a|b) = a or b   \"? = an optional quote (paths are often written in quotes)

def rule(pattern, what, tactic, technique):
    return re.compile(pattern, re.IGNORECASE), what, tactic, technique


# Running commands on another computer. Admins do this every day, so these are Weak.
REMOTE_EXECUTION_RULES = [
    # PsExec / PaExec followed by a computer: "PsExec64.exe \\SRV-01 cmd"
    rule(r"\b(ps|pa)exec(64)?(\.exe)?\"?\s.*\\\\[a-z0-9._-]+", "runs a program on another computer with PsExec",
         "Lateral Movement", "T1021.002 SMB/Windows Admin Shares"),
    # WMI on another computer: "wmic /node:SRV-01 process call create ..."
    rule(r"\bwmic(\.exe)?\b.*\s/node:", "runs a command on another computer with WMI",
         "Execution", "T1047 Windows Management Instrumentation"),
    # Windows Remote Shell: "winrs -r:SRV-01 cmd"
    rule(r"\bwinrs(\.exe)?\b.*\s[-/]r(emote)?:", "runs a command on another computer with WinRS",
         "Lateral Movement", "T1021.006 Windows Remote Management"),
    # PowerShell remoting: Invoke-Command -ComputerName ..., Enter-PSSession, New-PSSession
    rule(r"invoke-command\b.*-computername|enter-pssession|new-pssession",
         "runs PowerShell on another computer", "Lateral Movement", "T1021.006 Windows Remote Management"),
    # A scheduled task or service on another computer: "schtasks /create /s SRV-01 ...", "sc \\SRV-01 create"
    rule(r"\bschtasks(\.exe)?\b.*\s/s\s+\S", "creates or changes a scheduled task on another computer",
         "Lateral Movement", "T1053.005 Scheduled Task"),
    rule(r"\bsc(\.exe)?\"?\s+\\\\[a-z0-9._-]+", "creates or changes a service on another computer",
         "Lateral Movement", "T1569.002 Service Execution"),
    # An admin share: \\SRV-01\C$ or \\SRV-01\ADMIN$ (copying tools there, or "net use" to it)
    rule(r"\\\\[a-z0-9._-]+\\([a-z]|admin)\$", "uses an administrative share on another computer",
         "Lateral Movement", "T1570 Lateral Tool Transfer"),
]

# Creating accounts, giving admin rights, opening the firewall. Admins do this too: Weak.
ACCESS_CHANGE_RULES = [
    # "net user helpdesk **** /add" (net1.exe is the same tool)
    rule(r"\bnet1?(\.exe)?\"?\s+user\s+\S+.*\s/add\b", "creates a user account",
         "Persistence", "T1136.001 Local Account"),
    # "net localgroup Administrators helpdesk /add", also Domain Admins and Remote Desktop Users
    rule(r"\bnet1?(\.exe)?\"?\s+(localgroup|group)\s+\"?(administrators|domain admins|enterprise admins|"
         r"remote desktop users)\"?\s+\S+.*\s/add\b", "adds an account to a privileged group",
         "Persistence", "T1098 Account Manipulation"),
    # The same with PowerShell: New-LocalUser, Add-LocalGroupMember -Group Administrators
    rule(r"new-localuser\b", "creates a user account", "Persistence", "T1136.001 Local Account"),
    rule(r"add-localgroupmember\b.*(administrators|remote desktop users)", "adds an account to a privileged group",
         "Persistence", "T1098 Account Manipulation"),
    # "netsh advfirewall firewall set rule ... enable=yes", "netsh firewall add ..."
    rule(r"\bnetsh(\.exe)?\b.*\bfirewall\b.*\b(add|set|delete)\b", "changes the Windows firewall",
         "Defense Evasion", "T1562.004 Disable or Modify System Firewall"),
]

# A new scheduled task (it runs again later, often as SYSTEM). Many admin and update tools do
# this too: Weak.
SCHEDULED_TASK_RULES = [
    rule(r"\bschtasks(\.exe)?\b.*\s/create\b", "creates a scheduled task", "Persistence", "T1053.005 Scheduled Task"),
    rule(r"register-scheduledtask\b", "creates a scheduled task", "Persistence", "T1053.005 Scheduled Task"),
]

# Windows programs that are not download tools but can be misused to download files
# ("living off the land"). curl.exe is a real download tool, so it is not on this list. Weak.
TOOL_DOWNLOAD_RULES = [
    # "certutil -urlcache -split -f http://.../a.dat a.dat", "certutil -decode in.txt out.exe"
    rule(r"\bcertutil(\.exe)?\b.*\s[-/](urlcache|verifyctl)\b", "downloads a file with certutil",
         "Command and Control", "T1105 Ingress Tool Transfer"),
    rule(r"\bcertutil(\.exe)?\b.*\s[-/]decode\b", "decodes a file with certutil",
         "Defense Evasion", "T1140 Deobfuscate/Decode Files or Information"),
    # "bitsadmin /transfer job http://.../a.exe C:\a.exe"
    rule(r"\bbitsadmin(\.exe)?\b.*\s/(transfer|addfile|download)\b", "downloads a file with bitsadmin",
         "Command and Control", "T1105 Ingress Tool Transfer"),
    # "mshta http://.../page.hta" (runs a web page as a program)
    rule(r"\bmshta(\.exe)?\"?\s+\"?https?://", "runs a web page with mshta",
         "Defense Evasion", "T1218.005 Mshta"),
    # "regsvr32 /s /u /i:http://.../file.sct scrobj.dll"
    rule(r"\bregsvr32(\.exe)?\b.*\s/i:\"?https?://", "runs a script from the internet with regsvr32",
         "Defense Evasion", "T1218.010 Regsvr32"),
]


def check_by_rules(events, check, title, strength, rules, skip_programs=()):
    """Shared by the command-line checks: one finding per program and rule, with the rule's
    own ATT&CK tag (so a PsExec line and a WMI line get different techniques).
    Programs in skip_programs are never checked (e.g. a browser reading its own password store).
    For PowerShell, the hidden text of an encoded command is searched too, so encoding cannot
    hide a command from these checks (ATT&CK T1027 Obfuscated Files or Information)."""
    found = {}
    for e in events_of(events, 1):
        if file_name(e.get("Image")) in skip_programs:
            continue
        command = e.get("CommandLine", "")
        shown = command
        if file_name(e.get("Image")) in ("powershell.exe", "pwsh.exe"):
            decoded = decode_powershell(command)
            if decoded:
                command = command + " " + decoded
                shown = "decoded command: " + decoded
        for pattern, what, tactic, technique in rules:
            if pattern.search(command):
                key = (file_name(e.get("Image")), what)
                add_finding(found, key, e, check, title, strength, e.get("Image", ""),
                            f"{file_name(e.get('Image'))} {what}: {shown[:180]}", e.get("ProcessGuid", ""))
                found[key]["tactic"], found[key]["technique"] = tactic, technique
                break  # one rule per command line is enough
    return list(found.values())


def check_remote_execution(events, context):
    """Weak: a command run on another computer (PsExec, WMI, WinRS, remoting, admin shares)."""
    return check_by_rules(events, "remote_execution", "Command run on another computer", "Weak",
                          REMOTE_EXECUTION_RULES)


def check_access_change(events, context):
    """Weak: a new account, an account added to an admin group, or a firewall change."""
    return check_by_rules(events, "access_change", "Account or firewall change", "Weak", ACCESS_CHANGE_RULES)


def check_scheduled_task(events, context):
    """Weak: a scheduled task was created."""
    return check_by_rules(events, "scheduled_task", "Scheduled task created", "Weak", SCHEDULED_TASK_RULES)


def check_tool_download(events, context):
    """Weak: a Windows program that is not a download tool was used to download or decode a file."""
    return check_by_rules(events, "tool_download", "Download with a Windows tool", "Weak", TOOL_DOWNLOAD_RULES)


# Stealing saved passwords. No common legitimate use outside the browser itself: Strong.
CREDENTIAL_THEFT_RULES = [
    # Browser password and cookie stores: Chrome/Edge "...\User Data\Default\Login Data" (also
    # Cookies, Web Data), Firefox "logins.json", "key4.db", "cookies.sqlite".
    # ^(?!.*\b(del|...)\b) = "the line has none of these delete words": a cleanup script deleting
    # cookies does not steal them.
    rule(r"^(?!.*\b(del|erase|rd|rmdir|remove-item)\b)"
         r".*(\\user data\\.*\b(login data|cookies|web data)\b|\b(logins\.json|key4\.db|cookies\.sqlite)\b)",
         "reads a browser's saved passwords or cookies", "Credential Access",
         "T1555.003 Credentials from Web Browsers"),
    # Dumping LSASS memory with Windows' own comsvcs.dll: "rundll32 comsvcs.dll, MiniDump 624 d.dmp full"
    rule(r"comsvcs(\.dll)?.*\b(minidump|#24)\b", "dumps LSASS memory with comsvcs.dll",
         "Credential Access", "T1003.001 LSASS Memory"),
    # "procdump -ma lsass.exe out.dmp"
    rule(r"\bprocdump(64)?(\.exe)?\b.*\s-ma\b.*\blsass", "dumps LSASS memory with ProcDump",
         "Credential Access", "T1003.001 LSASS Memory"),
    # Saving the password databases from the registry: "reg save HKLM\SAM sam.hiv"
    rule(r"\breg(\.exe)?\"?\s+(save|export)\s+\"?hklm\\(sam|security)\b",
         "copies the Windows password database (SAM/SECURITY)", "Credential Access",
         "T1003.002 Security Account Manager"),
    # Copying the domain password database: "ntdsutil "ac i ntds" "ifm" "create full C:\x""
    rule(r"\bntdsutil(\.exe)?\b.*\b(ifm|create full)\b", "copies the domain password database (NTDS)",
         "Credential Access", "T1003.003 NTDS"),
]

# Switching off the evidence: event logs, the Sysmon sensor, shadow copies and recovery.
# Not routine on a workstation: Strong.
EVIDENCE_REMOVAL_RULES = [
    # "wevtutil cl System", "wevtutil clear-log Security"
    rule(r"\bwevtutil(\.exe)?\"?\s+(cl|clear-log)\b", "clears an event log",
         "Defense Evasion", "T1070.001 Clear Windows Event Logs"),
    rule(r"\b(clear-eventlog|remove-eventlog)\b", "clears an event log",
         "Defense Evasion", "T1070.001 Clear Windows Event Logs"),
    # "fltmc unload SysmonDrv" (removes a security driver), "sysmon64 -u", "sc stop Sysmon64"
    rule(r"\bfltmc(\.exe)?\"?\s+unload\b", "unloads a security driver (e.g. Sysmon)",
         "Defense Evasion", "T1562.001 Disable or Modify Tools"),
    rule(r"\bsysmon(64)?(\.exe)?\"?\s+-u\b", "uninstalls Sysmon", "Defense Evasion", "T1562.001 Disable or Modify Tools"),
    rule(r"\b(sc|net)(\.exe)?\"?\s+(stop|delete)\s+\"?sysmon", "stops Sysmon",
         "Defense Evasion", "T1562.001 Disable or Modify Tools"),
    # Deleting the backups ransomware does not want you to restore from
    rule(r"\bvssadmin(\.exe)?\b.*\bdelete\s+shadows\b", "deletes shadow copies (backups)",
         "Impact", "T1490 Inhibit System Recovery"),
    rule(r"\bwmic(\.exe)?\b.*\bshadowcopy\b.*\bdelete\b", "deletes shadow copies (backups)",
         "Impact", "T1490 Inhibit System Recovery"),
    rule(r"\bwbadmin(\.exe)?\b.*\bdelete\s+(catalog|systemstatebackup)\b", "deletes Windows backups",
         "Impact", "T1490 Inhibit System Recovery"),
    rule(r"\bbcdedit(\.exe)?\b.*\brecoveryenabled\s+no\b", "turns off Windows recovery",
         "Impact", "T1490 Inhibit System Recovery"),
]

# Weakening Microsoft Defender. Admins sometimes add exclusions on purpose: Weak.
DEFENDER_RULES = [
    # "Set-MpPreference -DisableRealtimeMonitoring $true", "Add-MpPreference -ExclusionPath C:\x"
    rule(r"set-mppreference\b.*\s-disable", "turns off part of Microsoft Defender",
         "Defense Evasion", "T1562.001 Disable or Modify Tools"),
    rule(r"add-mppreference\b.*\s-exclusion", "adds a Microsoft Defender exclusion",
         "Defense Evasion", "T1562.001 Disable or Modify Tools"),
]
# The same in the registry, e.g. "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x"
# or "...\Policies\Microsoft\Windows Defender\DisableAntiSpyware" (.* = anything in between).
DEFENDER_REGISTRY = re.compile(r"\\windows defender\\(exclusions\\|.*disable)", re.IGNORECASE)

# The registry keys of known UAC bypasses: a program that Windows starts with admin rights
# without asking (fodhelper.exe, eventvwr.exe) reads its "open" command from the user's own
# registry, so writing that key gives admin rights silently. No legitimate use: Strong.
# Matched anywhere in the key, so both "HKU\<SID>\Software\Classes\ms-settings\..." and the
# "HKU\<SID>_Classes\ms-settings\..." form that Sysmon also writes are caught (ATT&CK T1548.002).
UAC_BYPASS_KEY = re.compile(r"\\(ms-settings|mscfile)\\shell\\open\\command", re.IGNORECASE)


def check_credential_theft(events, context):
    """Strong: stealing saved passwords (browser stores, LSASS dumps, SAM/NTDS copies).
    A browser reading its own files is skipped."""
    return check_by_rules(events, "credential_theft", "Saved passwords stolen", "Strong",
                          CREDENTIAL_THEFT_RULES, skip_programs=BROWSERS)


def check_evidence_removal(events, context):
    """Strong: event logs cleared, Sysmon switched off, backups or recovery deleted."""
    return check_by_rules(events, "evidence_removal", "Logs, sensor or backups switched off", "Strong",
                          EVIDENCE_REMOVAL_RULES)


def check_defender_weakened(events, context):
    """Weak: Microsoft Defender turned off in part, or an exclusion added (command line or registry)."""
    found = {}
    for f in check_by_rules(events, "defender_weakened", "Microsoft Defender weakened", "Weak", DEFENDER_RULES):
        found[(f["process"].lower(), f["detail"])] = f
    for e in events_of(events, 12) + events_of(events, 13):
        target = e.get("TargetObject", "")
        if not DEFENDER_REGISTRY.search(target):
            continue
        if file_name(e.get("Image")) == "msmpeng.exe":
            continue  # Defender updating its own settings
        if "disable" in target.lower() and e.get("Details", "").endswith("0x00000000)"):
            continue  # a "Disable..." value set to 0 turns protection ON
        add_finding(found, ("registry", target.lower()), e, "defender_weakened", "Microsoft Defender weakened",
                    "Weak", e.get("Image", ""), f"{file_name(e.get('Image'))} changed {target[:180]}",
                    e.get("ProcessGuid", ""))
    return list(found.values())


def check_uac_bypass(events, context):
    """Strong: a known UAC-bypass registry key was written (silent admin rights)."""
    found = {}
    for e in events_of(events, 12) + events_of(events, 13):
        target = e.get("TargetObject", "")
        if UAC_BYPASS_KEY.search(target):
            add_finding(found, target.lower(), e, "uac_bypass", "Admin rights taken without asking (UAC bypass)",
                        "Strong", e.get("Image", ""),
                        f"{file_name(e.get('Image'))} wrote {target[:150]} = {e.get('Details', '')[:120]}",
                        e.get("ProcessGuid", ""))
    return list(found.values())


# A DLL path in a command line, e.g. "C:\Users\a\AppData\Roaming\x\update.dll":
# a drive letter, :\, then any characters except quotes and commas, up to ".dll".
DLL_PATH = re.compile(r"[a-z]:\\[^\",]*?\.dll", re.IGNORECASE)


def check_dll_from_user_folder(events, context):
    """Weak: rundll32 or regsvr32 runs a DLL from a user folder (Downloads, AppData, Temp...)."""
    found = {}
    for e in events_of(events, 1):
        if file_name(e.get("Image")) not in ("rundll32.exe", "regsvr32.exe"):
            continue
        for dll in DLL_PATH.findall(e.get("CommandLine", "")):
            if in_user_folder(dll):
                add_finding(found, dll.lower(), e, "dll_from_user_folder", "DLL run from a user folder", "Weak",
                            e.get("Image", ""), f"{file_name(e.get('Image'))} ran {dll}", e.get("ProcessGuid", ""))
                break
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
    check_script_host_online,
    check_remote_access_tool,
    check_web_shell,
    check_archive,
    check_copy_to_other_drive,
    check_cloud_upload,
    check_remote_execution,
    check_access_change,
    check_scheduled_task,
    check_tool_download,
    check_dll_from_user_folder,
    check_credential_theft,
    check_evidence_removal,
    check_defender_weakened,
    check_uac_bypass,
]


# ---------- the dual-use gate ----------
# Some Strong behaviours also have a common legitimate version: recon by an admin or monitoring
# (RMM) tool, a security product reading LSASS, a lookalike-looking domain, an install script that
# downloads and runs code, a new service. On its own such a finding is Low. It stays High when:
#   1. the program itself or the program that started it runs from a user folder: admin and RMM
#      tools are installed in Program Files. The program that WROTE its file counts here only
#      when the analyst says IT installs all software (a sidebar switch): where users install
#      their own software, a setup program in Downloads is how normal tools arrive; or
#   2. that chain program is a proxy host (rundll32, regsvr32, mshta: ATT&CK T1218, "System
#      Binary Proxy Execution"), which admins do not use to run commands; or
#   3. a High finding that is NOT dual-use shares a program with its chain (e.g. the same
#      program also deleted backups); or
#   4. a High finding of a DIFFERENT dual-use kind shares a program with its chain (e.g. recon
#      plus download-and-run, or recon plus an LSASS read): two different steps of an attack
#      in one chain are a coherent story, not one ambiguous action. (Two findings of the same
#      kind, e.g. two recon bursts, do not count.)
# Never dual-use (High on their own): disguised programs, ransom notes, stolen passwords,
# logs/backups deleted, UAC bypass, a document starting a shell.
DUAL_USE_CHECKS = {"recon_burst", "lookalike_domain", "suspicious_powershell", "lsass_access"}
SERVICE_TITLE = "New service from a dropped file"   # the dual-use part of check_persistence
PROXY_HOSTS = {"rundll32.exe", "regsvr32.exe", "mshta.exe"}


def is_dual_use(finding):
    return finding["check"] in DUAL_USE_CHECKS or finding["title"] == SERVICE_TITLE


def kind_of(finding):
    """What kind of action a finding is: its check, or its title for the two kinds of persistence."""
    return finding["title"] if finding["check"] == "persistence" else finding["check"]


def chain_of(finding, context):
    """ProcessGuid -> program path for the finding's program, the program that started it and
    the program that created its file (when they are in the log)."""
    chain = {finding["process_guid"]: finding["process"]}
    started = context["processes"].get(finding["process_guid"])
    if started:
        chain[started.get("ParentProcessGuid", "")] = started.get("ParentImage", "")
    creator = context["file_creators"].get(finding["process"].lower(), "")
    if creator in context["processes"]:
        chain[creator] = context["processes"][creator].get("Image", "")
    chain.pop("", None)
    return chain


def apply_dual_use_gate(findings, context):
    """Turn a dual-use Strong finding into Weak when nothing backs it up (rules 1-3 above)."""
    to_lower = []
    for f in findings:
        if f["strength"] != "Strong" or not is_dual_use(f):
            continue
        chain = chain_of(f, context)
        # The running programs: the finding's own program and the program that started it.
        started = context["processes"].get(f["process_guid"], {})
        programs = [f["process"], started.get("ParentImage", "")]
        if context["it_installs_all"]:
            programs += list(chain.values())  # also the program that wrote its file
        if any(in_user_folder(p) or file_name(p) in PROXY_HOSTS for p in programs):
            continue  # rules 1 and 2
        backed = False
        for other in findings:
            if other is f or other["strength"] != "Strong":
                continue
            if not set(chain) & set(chain_of(other, context)):
                continue  # not in the same process chain
            if not is_dual_use(other):
                backed = True  # rule 3
            elif kind_of(other) != kind_of(f):
                backed = True  # rule 4
        if not backed:
            to_lower.append(f)
    # Changed only after all were decided, so the order of the findings does not matter.
    for f in to_lower:
        f["strength"] = "Weak"
        f["detail"] += " (dual-use: no other high-confidence sign on this program)"


def run_checks(events, it_installs_all=False):
    """Run every check and return all findings, oldest first.
    it_installs_all: True when IT installs all software on this client (users never do), so a
    program installed from a user folder is itself a warning sign (see the dual-use gate)."""
    context = {
        "it_installs_all": it_installs_all,
        # ProcessGuid -> its process-creation event, to look up parents.
        "processes": {e["ProcessGuid"]: e for e in events_of(events, 1) if e.get("ProcessGuid")},
        # Every file created during the log (lowercase paths).
        "dropped_files": {e.get("TargetFilename", "").lower() for e in events_of(events, 11)},
        # Created file (lowercase path) -> the ProcessGuid of the program that wrote it.
        "file_creators": {e.get("TargetFilename", "").lower(): e.get("ProcessGuid", "")
                          for e in events_of(events, 11)},
    }
    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(events, context))
    apply_dual_use_gate(findings, context)
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
