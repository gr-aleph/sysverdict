"""Shared by all checks: the data lists, common program lists and small helpers.
This file imports no check file, so every check file can import from it."""

import ipaddress
import re
from pathlib import Path

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


# Folders a normal user can write to. Programs rarely need to run from here.
USER_FOLDER_MARKERS = ["\\users\\", "\\windows\\temp\\", "\\programdata\\", "\\$recycle.bin\\"]


SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
          "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe"}


RECON_TOOLS = {"whoami.exe", "ipconfig.exe", "systeminfo.exe", "net.exe", "net1.exe",
               "nltest.exe", "quser.exe", "hostname.exe", "tasklist.exe", "arp.exe",
               "netstat.exe", "route.exe", "nslookup.exe"}


# Shells that only pass a command on: the recon check looks past them to find who started it.
PASS_ON_SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe")


BROWSERS = {"msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "brave.exe",
            "opera.exe", "msedgewebview2.exe"}


# Two-part domain endings: in "shop.example.co.uk" the name is "example", not "co".
TWO_PART_ENDINGS = ("co.uk", "com.sg", "com.au", "co.jp")


# A Windows path such as C:\Users\x\report.pdf inside a command line (it ends at a quote,
# a space or the end of the text, so "video.mp4.exe" is read whole).
# Pieces: [a-z]:\\ = drive letter and backslash; [^\"]+? = the shortest run of characters
# that are not quotes; \.[a-z0-9]{2,4} = a file ending of 2-4 characters; (?=[\"\s]|$) =
# "followed by a quote, a space or the end", without including that character.
# (Also used by iocs.py and story.py.)
FILE_IN_TEXT = re.compile(r"[a-z]:\\[^\"]+?\.[a-z0-9]{2,4}(?=[\"\s]|$)", re.IGNORECASE)


# Programs that run scripts or other code for someone else (ATT&CK T1059 Command and Scripting
# Interpreter, T1218 System Binary Proxy Execution).
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
                "wscript.exe", "cscript.exe"}


SERVICE_TITLE = "New service from a dropped file"   # the dual-use part of check_persistence


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
