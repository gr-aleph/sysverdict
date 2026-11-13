"""Label each DNS lookup (Event 22) as a site the user likely visited, or a background request.

Sysmon does not record which page asked for a domain, so these are guesses, always worded "likely":
  1. A domain on the local ad/CDN/telemetry list -> "likely ad, CDN or telemetry".
  2. A browser lookup after more than 2 seconds of quiet -> "likely visited site"
     (a person clicked or typed, and the page started loading).
  3. A browser lookup within 2 seconds of the previous one -> "likely page resource"
     (the page loading its images, scripts and trackers).
  4. A lookup by a program that is not a browser -> "background (program)".
"""

from triage.checks_common import BROWSERS, file_name, load_list
from triage.iocs import check_shareable
from triage.parse import to_datetime

AD_CDN_DOMAINS = load_list("ad_cdn_domains.txt")
BURST_SECONDS = 2


def is_ad_or_cdn(domain):
    return any(domain == entry or domain.endswith("." + entry) for entry in AD_CDN_DOMAINS)


def classify_domains(events):
    """Return one row per DNS lookup: time, domain, program, label, event_id."""
    computer_names = {e["computer"].lower() for e in events if e.get("computer")}
    rows = []
    last_lookup = {}  # browser name -> time of its previous lookup

    for e in events:
        if e["event_id"] != 22:
            continue
        domain = e.get("QueryName", "").lower().rstrip(".")
        program = file_name(e.get("Image"))
        when = to_datetime(e["time"])

        if check_shareable("domain", domain, computer_names):
            label = "internal name"
        elif is_ad_or_cdn(domain):
            label = "likely ad, CDN or telemetry"
        elif program in BROWSERS:
            previous = last_lookup.get(program)
            quiet = previous is None or (when - previous).total_seconds() > BURST_SECONDS
            label = "likely visited site" if quiet else "likely page resource"
        else:
            label = "background (program)"

        if program in BROWSERS:
            last_lookup[program] = when

        rows.append({"time": e["time"], "domain": domain, "program": program,
                     "label": label, "event_id": e["record_id"]})
    return rows
