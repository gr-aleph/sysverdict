"""Checks for ATT&CK Defense Evasion (and Impact on backups): disguised programs,
removed evidence, a weakened Defender, UAC bypass, DLLs from user folders."""

import re

from triage.checks_common import add_finding, events_of, file_name, in_user_folder
from triage.checks_rules import check_by_rules, rule


# Real Windows programs that should only ever run from the Windows folder.
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "smss.exe",
                "winlogon.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe",
                "conhost.exe", "rundll32.exe", "explorer.exe"}


SYSTEM_FOLDERS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\winsxs\\",
                  "c:\\windows\\explorer.exe")


# A hidden window, -ExecutionPolicy Bypass or an encoded command alone is not a finding:
# management agents (Intune, RMM, monitoring) use them all day (measured: up to 30 times in one
# normal log), so they would bury the real signals.

# A file name with a fake document ending before a program ending, e.g. "invoice.pdf.exe".
# Part 1 is the fake ending (docx? = doc or docx, jpe?g = jpg or jpeg); part 2 is the real
# program ending; $ means it must be the end of the name.
DOUBLE_EXTENSION = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp3|mp4|avi|mov|mkv|zip|rar)"
    r"\.(exe|scr|com|bat|cmd|vbs|js|pif)$")


def check_masquerading(events, context):
    """Strong: 'video.mp4.exe' style names, or a Windows program name in the wrong folder."""
    found = {}
    for e in events_of(events, 1) + events_of(events, 11):
        path = e.get("Image", "") if e["event_id"] == 1 else e.get("TargetFilename", "")
        name = file_name(path)
        if DOUBLE_EXTENSION.search(name):
            detail = f"{name} hides its real type behind a double extension"
        elif (e["event_id"] == 1 and name in SYSTEM_NAMES
              and not path.lower().startswith(SYSTEM_FOLDERS)):
            detail = f"{name} is a Windows program name, but runs from {path}"
        else:
            continue
        add_finding(found, path.lower(), e, "masquerading", "Disguised program", "Strong", path,
                    detail, e.get("ProcessGuid", ""))
    return list(found.values())


# Switching off the evidence: event logs, the Sysmon sensor, shadow copies and recovery.
# Not routine on a workstation: Strong.
EVIDENCE_REMOVAL_RULES = [
    # "wevtutil cl System", "wevtutil clear-log Security"
    rule(r"\bwevtutil(\.exe)?\"?\s+(cl|clear-log)\b", "clears an event log",
         "Defense Evasion", "T1070.001 Clear Windows Event Logs"),
    rule(r"\b(clear-eventlog|remove-eventlog)\b", "clears an event log",
         "Defense Evasion", "T1070.001 Clear Windows Event Logs"),
    # "fltmc unload SysmonDrv" (removes a security driver), "sysmon64 -u", "sc stop Sysmon64"
    rule(r"\bfltmc(\.exe)?\"?\s+unload\b", "unloads a security driver (e.g. Sysmon)",
         "Defense Evasion", "T1562.001 Disable or Modify Tools"),
    rule(r"\bsysmon(64)?(\.exe)?\"?\s+-u\b", "uninstalls Sysmon", "Defense Evasion", "T1562.001 Disable or Modify Tools"),
    rule(r"\b(sc|net)(\.exe)?\"?\s+(stop|delete)\s+\"?sysmon", "stops Sysmon",
         "Defense Evasion", "T1562.001 Disable or Modify Tools"),
    # Deleting the backups ransomware does not want you to restore from
    rule(r"\bvssadmin(\.exe)?\b.*\bdelete\s+shadows\b", "deletes shadow copies (backups)",
         "Impact", "T1490 Inhibit System Recovery"),
    rule(r"\bwmic(\.exe)?\b.*\bshadowcopy\b.*\bdelete\b", "deletes shadow copies (backups)",
         "Impact", "T1490 Inhibit System Recovery"),
    rule(r"\bwbadmin(\.exe)?\b.*\bdelete\s+(catalog|systemstatebackup)\b", "deletes Windows backups",
         "Impact", "T1490 Inhibit System Recovery"),
    rule(r"\bbcdedit(\.exe)?\b.*\brecoveryenabled\s+no\b", "turns off Windows recovery",
         "Impact", "T1490 Inhibit System Recovery"),
]


def check_evidence_removal(events, context):
    """Strong: event logs cleared, Sysmon switched off, backups or recovery deleted."""
    return check_by_rules(events, "evidence_removal", "Logs, sensor or backups switched off", "Strong",
                          EVIDENCE_REMOVAL_RULES)


# Weakening Microsoft Defender. Admins sometimes add exclusions on purpose: Weak.
DEFENDER_RULES = [
    # "Set-MpPreference -DisableRealtimeMonitoring $true", "Add-MpPreference -ExclusionPath C:\x"
    rule(r"set-mppreference\b.*\s-disable", "turns off part of Microsoft Defender",
         "Defense Evasion", "T1562.001 Disable or Modify Tools"),
    rule(r"add-mppreference\b.*\s-exclusion", "adds a Microsoft Defender exclusion",
         "Defense Evasion", "T1562.001 Disable or Modify Tools"),
]


# The same in the registry, e.g. "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x"
# or "...\Policies\Microsoft\Windows Defender\DisableAntiSpyware" (.* = anything in between).
DEFENDER_REGISTRY = re.compile(r"\\windows defender\\(exclusions\\|.*disable)", re.IGNORECASE)


def check_defender_weakened(events, context):
    """Weak: Microsoft Defender turned off in part, or an exclusion added (command line or registry)."""
    found = {}
    for f in check_by_rules(events, "defender_weakened", "Microsoft Defender weakened", "Weak", DEFENDER_RULES):
        found[(f["process"].lower(), f["detail"])] = f
    for e in events_of(events, 12) + events_of(events, 13):
        target = e.get("TargetObject", "")
        if not DEFENDER_REGISTRY.search(target):
            continue
        if file_name(e.get("Image")) == "msmpeng.exe":
            continue  # Defender updating its own settings
        if "disable" in target.lower() and e.get("Details", "").endswith("0x00000000)"):
            continue  # a "Disable..." value set to 0 turns protection ON
        add_finding(found, ("registry", target.lower()), e, "defender_weakened", "Microsoft Defender weakened",
                    "Weak", e.get("Image", ""), f"{file_name(e.get('Image'))} changed {target[:180]}",
                    e.get("ProcessGuid", ""))
    return list(found.values())


# The registry keys of known UAC bypasses: a program that Windows starts with admin rights
# without asking (fodhelper.exe, eventvwr.exe) reads its "open" command from the user's own
# registry, so writing that key gives admin rights silently. No legitimate use: Strong.
# Matched anywhere in the key, so both "HKU\<SID>\Software\Classes\ms-settings\..." and the
# "HKU\<SID>_Classes\ms-settings\..." form that Sysmon also writes are caught (ATT&CK T1548.002).
UAC_BYPASS_KEY = re.compile(r"\\(ms-settings|mscfile)\\shell\\open\\command", re.IGNORECASE)


def check_uac_bypass(events, context):
    """Strong: a known UAC-bypass registry key was written (silent admin rights)."""
    found = {}
    for e in events_of(events, 12) + events_of(events, 13):
        target = e.get("TargetObject", "")
        if UAC_BYPASS_KEY.search(target):
            add_finding(found, target.lower(), e, "uac_bypass", "Admin rights taken without asking (UAC bypass)",
                        "Strong", e.get("Image", ""),
                        f"{file_name(e.get('Image'))} wrote {target[:150]} = {e.get('Details', '')[:120]}",
                        e.get("ProcessGuid", ""))
    return list(found.values())


# A DLL path in a command line, e.g. "C:\Users\a\AppData\Roaming\x\update.dll":
# a drive letter, :\, then any characters except quotes and commas, up to ".dll".
DLL_PATH = re.compile(r"[a-z]:\\[^\",]*?\.dll", re.IGNORECASE)


def check_dll_from_user_folder(events, context):
    """Weak: rundll32 or regsvr32 runs a DLL from a user folder (Downloads, AppData, Temp...)."""
    found = {}
    for e in events_of(events, 1):
        if file_name(e.get("Image")) not in ("rundll32.exe", "regsvr32.exe"):
            continue
        for dll in DLL_PATH.findall(e.get("CommandLine", "")):
            if in_user_folder(dll):
                add_finding(found, dll.lower(), e, "dll_from_user_folder", "DLL run from a user folder", "Weak",
                            e.get("Image", ""), f"{file_name(e.get('Image'))} ran {dll}", e.get("ProcessGuid", ""))
                break
    return list(found.values())
