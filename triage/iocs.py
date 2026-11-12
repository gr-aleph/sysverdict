"""Pull out the IOCs (indicators of compromise) tied to the findings, and decide which
ones may be sent to an enrichment backend.

An IOC is a plain dict:
    {"type": "sha256", "value": "1b53...", "process": "C:\\...\\FireEye.exe",
     "event_id": 16704, "enrich": True, "why_not": ""}

Only IOCs of flagged processes are listed (processes with a Strong finding, or with a Weak
finding when there is no Strong one), so the analyst gets a short list, not every hash in the log.

PRIVACY: only sha256 hashes, public IPv4 addresses and public domain names are ever marked
enrich=True. Usernames, hostnames, file paths, registry keys, private IPs and internal names
never leave the machine. This filter runs before any HTTP call.
"""

import ipaddress
import re
from urllib.parse import urlsplit

from triage.checks import TWO_PART_ENDINGS, is_windows_program

# Regular expressions (patterns for finding text). Reading guide:
#   ? = the character before is optional   + = one or more   [^...] = any character except these
#   \s = a space   {2,} = two or more   re.IGNORECASE = upper and lower case both match

# A web address, e.g. https://www.example.com/file.exe: "http", an optional "s", "://",
# then everything up to the next space, quote or angle bracket.
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
# An email address, e.g. name@example.com: name characters, "@", the domain, a dot and an
# ending of at least two letters.
EMAIL_PATTERN = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)
INTERNAL_SUFFIXES = (".local", ".localdomain", ".lan", ".internal", ".corp", ".home",
                     ".intranet", ".arpa", ".localhost", ".test", ".invalid")
ENRICHABLE_TYPES = ("sha256", "ip", "domain")


# A Windows path such as C:\Users\x\report.pdf inside a command line (it ends at a quote,
# a space or the end of the text, so "video.mp4.exe" is read whole).
# Pieces: [a-z]:\\ = drive letter and backslash; [^\"]+? = the shortest run of characters
# that are not quotes; \.[a-z0-9]{2,4} = a file ending of 2-4 characters; (?=[\"\s]|$) =
# "followed by a quote, a space or the end", without including that character.
FILE_IN_TEXT = re.compile(r"[a-z]:\\[^\"]+?\.[a-z0-9]{2,4}(?=[\"\s]|$)", re.IGNORECASE)


def flagged_processes(findings):
    """Return (set of ProcessGuids, set of lowercase image paths) of the flagged processes."""
    strong = [f for f in findings if f["strength"] == "Strong"]
    chosen = strong or findings
    guids, images = set(), set()
    for f in chosen:
        if f["process_guid"]:
            guids.add(f["process_guid"])
        # Matching by path catches every run of a malicious program, but not of Windows' own
        # programs (powershell.exe, cmd.exe...), which also run for normal reasons.
        if f["process"] and not is_windows_program(f["process"]):
            images.add(f["process"].lower())
    return guids, images


def organisation_suffixes(computer_names):
    """The organisation's DNS suffix from each full computer name: 'pc01.contoso.com' -> 'contoso.com',
    plus its parent domain: 'pc01.ad.contoso.com' -> 'ad.contoso.com' and 'contoso.com' (so
    vpn.contoso.com stays private too). A suffix needs at least one dot, so a name like 'pc01.com'
    never marks every .com domain internal."""
    suffixes = set()
    for computer in computer_names:
        if "." in computer:
            suffix = computer.split(".", 1)[1]
            if "." in suffix:
                suffixes.add(suffix)
                # The parent domain: the last 2 labels, or 3 for endings like co.uk.
                labels = suffix.split(".")
                keep = 3 if ".".join(labels[-2:]) in TWO_PART_ENDINGS else 2
                if len(labels) > keep:
                    suffixes.add(".".join(labels[-keep:]))
    return suffixes


def url_host(url):
    """The host of a web address, without a user name, password or port:
    'https://bob:****@evil.example.com:8080/x' -> 'evil.example.com'. "" if there is none."""
    try:
        return urlsplit(url).hostname or ""
    except ValueError:  # a broken address, e.g. an unclosed [ of an IPv6 host
        return ""


def check_shareable(ioc_type, value, computer_names):
    """Return "" if this IOC may be sent for enrichment, else the reason it may not."""
    if ioc_type not in ENRICHABLE_TYPES:
        return "no enrichment backend for this type"

    if ioc_type == "sha256":
        # A SHA256 hash is exactly 64 hexadecimal characters (0-9 and a-f).
        return "" if re.fullmatch(r"[0-9a-f]{64}", value) else "not a valid SHA256"

    if ioc_type == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return "not a valid IP address"
        if ip.version == 6:
            return "IPv6 is not supported by the IP backend"
        if not ip.is_global:
            return "private or reserved address (stays on this machine)"
        return ""

    # domain
    if "." not in value or value.startswith("_"):
        return "internal name (stays on this machine)"
    if value.endswith(INTERNAL_SUFFIXES):
        return "internal domain (stays on this machine)"
    for computer in computer_names:
        if value == computer or value.startswith(computer + "."):
            return "this computer's own name (stays on this machine)"
    # The organisation's own domains (fileserver.contoso.com for computer pc01.contoso.com).
    for suffix in organisation_suffixes(computer_names):
        if value == suffix or value.endswith("." + suffix):
            return "internal domain of this organisation (stays on this machine)"
    try:
        ipaddress.ip_address(value)
        return "an IP address, not a domain"
    except ValueError:
        pass
    # A plain domain name uses only letters, digits, dots and dashes (fullmatch = the whole value).
    if not re.fullmatch(r"[a-z0-9.-]+", value):
        return "not a plain public domain name"
    return ""


def extract_iocs(events, findings):
    """Return the list of IOC dicts for the flagged processes, without duplicates."""
    events_by_id = {e["record_id"]: e for e in events}
    guids, images = flagged_processes(findings)
    computer_names = {e["computer"].lower() for e in events if e.get("computer")}

    iocs = {}

    def add(ioc_type, value, event):
        value = value.strip().lower().rstrip(".")
        if not value or (ioc_type, value) in iocs:
            return
        why_not = check_shareable(ioc_type, value, computer_names)
        iocs[(ioc_type, value)] = {"type": ioc_type, "value": value, "process": event.get("Image", ""),
                                   "event_id": event["record_id"], "enrich": why_not == "",
                                   "why_not": why_not}

    def is_flagged(event):
        return event.get("ProcessGuid") in guids or event.get("Image", "").lower() in images

    # Files named in the command lines of flagged processes, of the document app that started
    # them (e.g. the .rtf WordPad opened) and of a ransom-note finding (e.g. C:\Ransom.txt).
    opened_files = set()
    for f in findings:
        if f["check"] in ("document_app_spawns_program", "ransom_note"):
            for event_id in f["event_ids"]:
                e = events_by_id[event_id]
                parent = next((p for p in events if p["event_id"] == 1
                               and p.get("ProcessGuid") == e.get("ParentProcessGuid")), None)
                for source in (e, parent):
                    if source:
                        for path in FILE_IN_TEXT.findall(source.get("CommandLine", "")):
                            if not path.lower().endswith(".exe"):
                                add("file", path, source)
                                opened_files.add(path.lower())

    for e in events:
        event_id = e["event_id"]
        if event_id == 1 and is_flagged(e):
            add("file", e.get("Image", ""), e)
            for part in e.get("Hashes", "").split(","):
                name, _, value = part.partition("=")
                if name.upper() == "SHA256":
                    add("sha256", value, e)
                elif name.upper() == "IMPHASH":
                    add("imphash", value, e)
            for path in FILE_IN_TEXT.findall(e.get("CommandLine", "")):
                opened_files.add(path.lower())
        elif event_id == 3 and is_flagged(e):
            add("ip", e.get("DestinationIp", ""), e)
        elif event_id == 22 and is_flagged(e):
            add("domain", e.get("QueryName", ""), e)
        elif event_id == 11 and is_flagged(e):
            if ":zone.identifier" not in e.get("TargetFilename", "").lower():
                add("file", e.get("TargetFilename", ""), e)
        elif event_id in (12, 13, 14) and is_flagged(e):
            add("registry", e.get("TargetObject", ""), e)

        # Emails and URLs written in command lines or registry values of flagged processes.
        if is_flagged(e):
            text = e.get("CommandLine", "") + " " + e.get("Details", "")
            for url in URL_PATTERN.findall(text):
                add("url", url, e)
            for email in EMAIL_PATTERN.findall(text):
                add("email", email, e)

    # Registry keys that a finding points at directly (a service key is written by services.exe).
    for f in findings:
        for event_id in f["event_ids"]:
            e = events_by_id[event_id]
            if e["event_id"] in (12, 13, 14) and f["strength"] == "Strong":
                add("registry", e.get("TargetObject", ""), e)

    # Where flagged files were downloaded from: Event 15 keeps the browser's Zone.Identifier.
    for e in events:
        if e["event_id"] != 15:
            continue
        target = e.get("TargetFilename", "").lower().replace(":zone.identifier", "")
        if target in images or target in opened_files:
            for url in URL_PATTERN.findall(e.get("Contents", "")):
                add("url", url, e)

    # Every URL's host is also an IOC: an IP (http://1.2.3.4/a) or a domain.
    for ioc in list(iocs.values()):
        if ioc["type"] == "url":
            host = url_host(ioc["value"])
            if not host:
                continue
            try:
                ipaddress.ip_address(host)
                host_type = "ip"
            except ValueError:
                host_type = "domain"
            add(host_type, host, events_by_id[ioc["event_id"]])

    # Domains that a finding is about (e.g. a lookalike domain from a browser).
    for f in findings:
        if f["check"] == "lookalike_domain":
            e = events_by_id[f["event_ids"][0]]
            add("domain", e.get("QueryName", ""), e)

    order = ["sha256", "ip", "domain", "url", "email", "imphash", "file", "registry"]
    return sorted(iocs.values(), key=lambda i: (order.index(i["type"]), i["value"]))
