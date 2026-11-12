"""Times, days and raw-event rows.

Sysmon records UTC. The page shows UTC, or (if the analyst picks a zone) local time only,
grouped under "Day 1 · Wed 13 Dec 2023" headers so the date is printed once, not on every row.
"""

from zoneinfo import ZoneInfo

from triage.parse import to_datetime

# Official Sysmon event names, so the analyst can search for the same ID in any tool.
EVENT_NAMES = {1: "Process Create", 2: "File creation time changed", 3: "Network connection detected",
               4: "Sysmon service state changed", 5: "Process terminated", 6: "Driver loaded",
               7: "Image loaded", 8: "CreateRemoteThread", 9: "RawAccessRead", 10: "ProcessAccess",
               11: "FileCreate", 12: "RegistryEvent (Object create and delete)",
               13: "RegistryEvent (Value Set)", 14: "RegistryEvent (Key and Value Rename)",
               15: "FileCreateStreamHash", 16: "ServiceConfigurationChange", 17: "PipeEvent (Pipe Created)",
               18: "PipeEvent (Pipe Connected)", 19: "WmiEvent (WmiEventFilter)",
               20: "WmiEvent (WmiEventConsumer)", 21: "WmiEvent (WmiEventConsumerToFilter)",
               22: "DNSEvent (DNS query)", 23: "FileDelete (File Delete archived)", 24: "ClipboardChange",
               25: "ProcessTampering", 26: "FileDeleteDetected", 27: "FileBlockExecutable",
               28: "FileBlockShredding", 29: "FileExecutableDetected", 255: "Error"}

# Choices for the time zone. None means UTC.
TIME_ZONES = {"UTC": None, "Singapore (UTC+8)": "Asia/Singapore", "Manila (UTC+8)": "Asia/Manila",
              "Jakarta (UTC+7)": "Asia/Jakarta", "Tokyo (UTC+9)": "Asia/Tokyo",
              "Sydney": "Australia/Sydney", "London": "Europe/London", "New York (US Eastern)": "America/New_York",
              "Dallas, TX (US Central)": "America/Chicago", "Los Angeles, CA (US Pacific)": "America/Los_Angeles"}


def event_label(event_id):
    """1 -> '1 – Process Create'."""
    return f"{event_id} – {EVENT_NAMES.get(event_id, 'Unknown')}"


def in_zone(time_text, zone_name=None):
    """UTC time text -> datetime in the chosen zone (or UTC)."""
    moment = to_datetime(time_text)
    return moment.astimezone(ZoneInfo(zone_name)) if zone_name else moment


def group_by_day(items, zone_name=None):
    """Group items that have a "time" key by day.

    Returns [("Day 1 · Wed 13 Dec 2023", [("10:53:39", item), ...]), ...]. Day 1 is the day of
    the first item, in the chosen zone.
    """
    groups = []
    first_date = None
    for item in items:
        moment = in_zone(item["time"], zone_name)
        if first_date is None:
            first_date = moment.date()
        label = f"Day {(moment.date() - first_date).days + 1} · {moment.strftime('%a %d %b %Y')}"
        if not groups or groups[-1][0] != label:
            groups.append((label, []))
        groups[-1][1].append((moment.strftime("%H:%M:%S"), item))
    return groups


def time_column(zone_name=None):
    """Name of the time column: UTC, or local time only when a zone is chosen."""
    return "Time (UTC)" if zone_name is None else "Local time"
