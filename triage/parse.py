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

import Evtx.Evtx as evtx

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


def hide_secrets(text):
    """Replace passwords in a command line or value by ****:
    'net use \\\\pc\\c$ Secret1 /user:admin' -> 'net use \\\\pc\\c$ **** /user:admin'.
    Limit: a password written as a plain word with no option name in front cannot be recognised."""
    for pattern in (PASSWORD_OPTION, PASSWORD_SETTING, NET_USE_PASSWORD):
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


def read_evtx(path):
    """Read a whole .evtx file and return its Sysmon events, oldest first."""
    events = []
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                event = event_from_xml(record.xml())
            except Exception:
                # A damaged record (bad XML, or an error inside python-evtx while decoding it):
                # skip it rather than fail the whole file.
                continue
            if event is not None:
                events.append(event)

    events.sort(key=lambda e: (e["time"], e["record_id"]))
    return events


def to_datetime(time_text):
    """Turn "2023-12-13 10:26:11.482" into a timezone-aware UTC datetime."""
    return datetime.fromisoformat(time_text).replace(tzinfo=timezone.utc)
