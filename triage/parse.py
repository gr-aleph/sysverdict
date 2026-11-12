"""Read a Sysmon .evtx file and turn every event into a plain Python dict.

One event becomes one dict, for example:
    {"record_id": 16221, "event_id": 1, "time": "2023-12-13 10:26:11.482",
     "computer": "PC01", "Image": "C:\\Windows\\System32\\LogonUI.exe", ...}

Every field from the event's <EventData> section is copied as-is, so the rest of the
program can use the Sysmon field names (Image, ParentImage, CommandLine, QueryName, ...).
The record_id is what lets every finding point back to the raw event.
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# The evtx package (pyevtx-rs) is written in Rust: about 65 times faster than python-evtx
# (the FireEye sample: 0.13 s instead of 8.6 s) and gives the same events.
from evtx import PyEvtxParser

# Windows event XML puts every tag in this namespace.
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"

# ---------- hiding passwords ----------
# Command lines and registry values can contain passwords. They are replaced by **** as soon as
# an event is read, so no tab, export or raw-event view ever shows them.
HIDDEN = "****"

# 1. A password option and its value: "/p:Secret1", "-pw Secret1", "--password=Secret1",
#    "-Password 'Secret 1'", "schtasks ... /rp Secret1". Read it as: (start of text or a space)
#    then / or - or --, then one of the option names, then ":" "=" or spaces, then the value: a
#    quoted text or a run of non-space characters (\S+). The option part is kept (group 1); only
#    the value is replaced. (?![-/]) means the value may not start with - or /: then it is the next
#    option, as in Windows' own "svchost.exe -k netsvcs -p -s Schedule", where -p has no value.
#    A few tools use /p for something else (xcopy /p = "prompt"); then the next word is hidden
#    too, which is the safe mistake to make.
PASSWORD_OPTION = re.compile(
    r"((?:^|\s)(?:/|--?)(?:p|pw|pwd|rp|pass|passwd|password)(?:[:=]\s*|\s+))"
    r"(?![-/])(\"[^\"]*\"|'[^']*'|\S+)",
    re.IGNORECASE)

# 2. "password=..." or "pwd=..." inside a text, e.g. a connection string "Server=x;Pwd=Secret1;".
#    [^;\s"']+ = the value: characters up to a ";", a space or a quote.
PASSWORD_SETTING = re.compile(r"(\b(?:password|passwd|pwd)\s*[=:]\s*)([^;\s\"']+)", re.IGNORECASE)

# 3. "net use \\server\share Secret1 /user:admin": the word after the share is the password.
#    (?:[a-z]:\s+)? allows a drive letter first ("net use z: \\server\share ..."); (?!/) means
#    the next word is not an option such as /user.
NET_USE_PASSWORD = re.compile(
    r"(\bnet1?(?:\.exe)?\s+use\s+(?:[a-z]:\s+)?\\\\\S+\s+)(?!/)(\"[^\"]*\"|\S+)",
    re.IGNORECASE)

# 4. "net user helpdesk Secret1 /add": the word after the user name is the password.
#    \"? allows "net.exe" in quotes; (?!/) means the user name is not an option such as /domain;
#    (?![/*]) means the next word is not an option (/add) and not * (= ask for the password).
NET_USER_PASSWORD = re.compile(
    r"(\bnet1?(?:\.exe)?\"?\s+user\s+(?!/)(?:\"[^\"]*\"|\S+)\s+)(?![/*])(\"[^\"]*\"|\S+)",
    re.IGNORECASE)


# 5. "net use \\server\share /user:admin Secret1": the password written AFTER the user name.
#    .*? = anything up to the first /user: (or /u:); (?![/*]) = the next word is not an option.
NET_USE_PASSWORD_AFTER_USER = re.compile(
    r"(\bnet1?(?:\.exe)?\"?\s+use\b.*?\s/u(?:ser)?:\S+\s+)(?![/*])(\"[^\"]*\"|\S+)",
    re.IGNORECASE)

# 6. A password glued to -p, as 7-Zip and MySQL accept it: "7z x a.zip -pSecret1",
#    "mysql -u root -pSecret1". Only for these programs: for other tools "-pXYZ" means something
#    else. (?i:...) ignores case for the program name only; "-p" itself must be lowercase,
#    because MySQL's "-P3306" (capital P) is a port number. (?=[^\s-]) = something follows at once.
GLUED_PASSWORD = re.compile(
    r"(\b(?i:7za?|mysql)(?i:\.exe)?\"?\s(?:.*\s)?-p)(?=[^\s\"-])(\S+)")

# 7. A user name and password inside a web address: "https://bob:Secret1@host/x".
#    (?=@) = "followed by @", so the @ and the host stay as they are.
URL_PASSWORD = re.compile(r"(://[^\s/:@]+:)([^\s/@]+)(?=@)")

# 8. "-u user:password", as curl writes it: "curl -u bob:Secret1 https://host".
USER_COLON_PASSWORD = re.compile(r"((?:^|\s)-u\s+\"?[^\s:\"]+:)([^\s\"]+)")


def hide_secrets(text):
    """Replace passwords in a command line or value by ****:
    'net use \\\\pc\\c$ Secret1 /user:admin' -> 'net use \\\\pc\\c$ **** /user:admin'.
    Limit: a password written as a plain word with no option name in front cannot be recognised."""
    for pattern in (PASSWORD_OPTION, PASSWORD_SETTING, NET_USE_PASSWORD, NET_USER_PASSWORD,
                    NET_USE_PASSWORD_AFTER_USER, GLUED_PASSWORD, URL_PASSWORD, USER_COLON_PASSWORD):
        text = pattern.sub(lambda match: match.group(1) + HIDDEN, text)
    return text


def event_from_xml(xml_text):
    """Turn the XML of one event into a dict. Returns None for non-Sysmon events."""
    root = ET.fromstring(xml_text)
    system = root.find(NS + "System")

    provider = system.find(NS + "Provider").get("Name", "")
    if provider != SYSMON_PROVIDER:
        return None

    event = {
        "record_id": int(system.findtext(NS + "EventRecordID", "0")),
        "event_id": int(system.findtext(NS + "EventID", "0")),
        "computer": system.findtext(NS + "Computer", ""),
        # SystemTime looks like "2023-12-13 10:26:11.484695+00:00"; keep up to milliseconds.
        "time": system.find(NS + "TimeCreated").get("SystemTime", "")[:23],
    }

    # Copy every <Data Name="...">value</Data> into the dict, with any password hidden.
    for data in root.iter(NS + "Data"):
        name = data.get("Name")
        if name:
            event[name] = hide_secrets(data.text or "")

    # Sysmon's own UtcTime is the moment the action happened, so prefer it.
    if event.get("UtcTime"):
        event["time"] = event["UtcTime"]

    return event


def read_evtx_with_status(path):
    """Read a whole .evtx file. Returns (Sysmon events oldest first, damaged), where damaged is
    True when the reader had to stop early: the events read up to that point are still returned."""
    events = []
    damaged = False
    # records() gives one dict per event; record["data"] is the event's XML text.
    # The reader itself skips records it cannot decode, so a damaged part of the file
    # does not stop the rest.
    records = iter(PyEvtxParser(str(path)).records())
    while True:
        try:
            record = next(records)
        except StopIteration:
            break  # the normal end of the file
        except (RuntimeError, OSError):
            damaged = True  # the reader itself gave up (a cut-off or broken file)
            break
        try:
            event = event_from_xml(record["data"])
            if event is not None:
                to_datetime(event["time"])  # fails (ValueError) for a time we cannot read
        except Exception:
            # A record whose XML or time we cannot read: skip it rather than fail the whole file.
            continue
        if event is not None:
            events.append(event)

    events.sort(key=lambda e: (e["time"], e["record_id"]))
    return events, damaged


def read_evtx(path):
    """Read a whole .evtx file and return its Sysmon events, oldest first."""
    return read_evtx_with_status(path)[0]


def to_datetime(time_text):
    """Turn "2023-12-13 10:26:11.482" into a timezone-aware UTC datetime."""
    return datetime.fromisoformat(time_text).replace(tzinfo=timezone.utc)
