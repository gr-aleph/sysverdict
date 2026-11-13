"""The command-line rule lists' engine: rule(), check_by_rules() and decoding of
PowerShell -EncodedCommand, so an encoded command is checked like a plain one."""

import base64
import re

from triage.checks_common import add_finding, events_of, file_name
from triage.parse import hide_secrets


# PowerShell is judged by what the command DOES, after decoding an encoded command.
# Encoding alone is not a finding: monitoring agents and admins encode commands too.
# Reading guide for the regular expressions below:
#   \s = a space   [a-z]* = any letters   + = one or more   {20,} = 20 or more
#   | = "or"       \b = a word edge (so "iex" does not match inside "index")   ( ) = the part we keep

# "-enc" / "-e" / "-EncodedCommand" followed by base64 text (the hidden command), e.g.
# "powershell -EncodedCommand aQB3AHIA...". Group 1 is the base64 text.
ENCODED_COMMAND = re.compile(r"\s-e[a-z]*\s+([a-z0-9+/=]{20,})", re.IGNORECASE)


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


# Each rule is (pattern, what it means, ATT&CK tactic, ATT&CK technique). The patterns are searched
# in a program's command line, ignoring upper/lower case. Reading guide for the patterns:
#   \b = a word edge   \s = a space   \S = not a space   .* = anything   (x)? = x is optional
#   \\\\ = the two backslashes of a network path (\\server)   [a-z0-9._-]+ = a computer name
#   (a|b) = a or b   \"? = an optional quote (paths are often written in quotes)

def rule(pattern, what, tactic, technique):
    return re.compile(pattern, re.IGNORECASE), what, tactic, technique


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
