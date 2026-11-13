"""Checks for ATT&CK Execution: documents, web servers or user folders starting programs,
and PowerShell that downloads or runs hidden code."""

import re

from triage.checks_common import (BROWSERS, RECON_TOOLS, SCRIPT_HOSTS, SHELLS, add_finding, events_of, file_name,
                                  in_user_folder)
from triage.checks_rules import decode_powershell


DOCUMENT_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
                 "msaccess.exe", "mspub.exe", "wordpad.exe", "acrord32.exe", "acrobat.exe",
                 "foxitpdfreader.exe"}


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


# PowerShell patterns (a reading guide for these regular expressions is in checks_rules.py).
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
