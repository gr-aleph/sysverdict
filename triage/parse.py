"""Read a Sysmon .evtx file and turn every event into a plain Python dict.

One event becomes one dict, for example:
    {"record_id": 16221, "event_id": 1, "time": "2023-12-13 10:26:11.482",
     "computer": "PC01", "Image": "C:\\Windows\\System32\\LogonUI.exe", ...}

Every field from the event's <EventData> section is copied as-is, so the rest of the
program can use the Sysmon field names (Image, ParentImage, CommandLine, QueryName, ...).
The record_id is what lets every finding point back to the raw event.
"""

import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import Evtx.Evtx as evtx

# Windows event XML puts every tag in this namespace.
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


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

    # Copy every <Data Name="...">value</Data> into the dict.
    for data in root.iter(NS + "Data"):
        name = data.get("Name")
        if name:
            event[name] = data.text or ""

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
