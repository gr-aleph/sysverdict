"""Checks for ATT&CK Command and Control: lookalike domains, programs and script hosts going
online, remote-access tools, Windows tools used to download files."""

from triage.checks_common import (BROWSERS, SCRIPT_HOSTS, TWO_PART_ENDINGS, add_finding, events_of, file_name,
                                  in_user_folder, is_public_ip, load_list)
from triage.checks_rules import check_by_rules, rule


BRANDS = load_list("brands.txt")


# Domains a brand owns itself, whose name part happens to be one letter from another brand
# (Microsoft 365 moved to *.cloud.microsoft; "cloud" is one letter from "icloud"). A lookup of
# one of these, or of a subdomain, is never a lookalike. Source: Microsoft's own domain list.
BRAND_OWNED_DOMAINS = ("cloud.microsoft",)


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


def check_tool_download(events, context):
    """Weak: a Windows program that is not a download tool was used to download or decode a file."""
    return check_by_rules(events, "tool_download", "Download with a Windows tool", "Weak", TOOL_DOWNLOAD_RULES)
