"""Checks for ATT&CK Credential Access: reading LSASS memory and stealing saved passwords."""

from triage.checks_common import BROWSERS, add_finding, events_of, file_name
from triage.checks_rules import check_by_rules, rule


# Programs that normally touch LSASS memory, and the folders they must run from to be trusted
# (a copy of MsMpEng.exe in a user folder is not Microsoft Defender).
LSASS_OK = {"svchost.exe", "msmpeng.exe", "wininit.exe", "csrss.exe", "wmiprvse.exe",
            "lsass.exe", "services.exe", "mrt.exe"}


# Only the system folders, not all of C:\Windows (C:\Windows\Temp is writable by everyone).
LSASS_OK_FOLDERS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                    "c:\\programdata\\microsoft\\windows defender\\",
                    "c:\\program files\\windows defender\\")


# The access right that lets a program read another program's memory (where passwords are).
PROCESS_VM_READ = 0x0010


def reads_memory(granted_access):
    """True if the access rights (hex text such as "0x1010") include PROCESS_VM_READ.
    An unknown or broken value counts as True: unknown access to LSASS is worth a look."""
    try:
        return (int(granted_access, 16) & PROCESS_VM_READ) != 0
    except (TypeError, ValueError):
        return True


def check_lsass_access(events, context):
    """Strong: a program opened LSASS, the process that holds Windows passwords, with the right
    to read its memory (Event 10)."""
    found = {}
    for e in events_of(events, 10):
        if not e.get("TargetImage", "").lower().endswith("\\lsass.exe"):
            continue
        if not reads_memory(e.get("GrantedAccess")):
            continue  # e.g. Task Manager asking only for basic information (0x1000)
        source = e.get("SourceImage", "")
        trusted_name = file_name(source) in LSASS_OK
        trusted_folder = source.lower().startswith(LSASS_OK_FOLDERS)
        if trusted_name and trusted_folder:
            continue
        add_finding(found, source.lower(), e, "lsass_access", "Credential access (LSASS)",
                    "Strong", source, f"{file_name(source)} opened lsass.exe "
                    f"(access {e.get('GrantedAccess', '?')})", e.get("SourceProcessGUID", ""))
    return list(found.values())


# Stealing saved passwords. No common legitimate use outside the browser itself: Strong.
CREDENTIAL_THEFT_RULES = [
    # Browser password and cookie stores: Chrome/Edge "...\User Data\Default\Login Data" (also
    # Cookies, Web Data), Firefox "logins.json", "key4.db", "cookies.sqlite".
    # ^(?!.*\b(del|...)\b) = "the line has none of these delete words": a cleanup script deleting
    # cookies does not steal them.
    rule(r"^(?!.*\b(del|erase|rd|rmdir|remove-item)\b)"
         r".*(\\user data\\.*\b(login data|cookies|web data)\b|\b(logins\.json|key4\.db|cookies\.sqlite)\b)",
         "reads a browser's saved passwords or cookies", "Credential Access",
         "T1555.003 Credentials from Web Browsers"),
    # Dumping LSASS memory with Windows' own comsvcs.dll: "rundll32 comsvcs.dll, MiniDump 624 d.dmp full"
    rule(r"comsvcs(\.dll)?.*\b(minidump|#24)\b", "dumps LSASS memory with comsvcs.dll",
         "Credential Access", "T1003.001 LSASS Memory"),
    # "procdump -ma lsass.exe out.dmp"
    rule(r"\bprocdump(64)?(\.exe)?\b.*\s-ma\b.*\blsass", "dumps LSASS memory with ProcDump",
         "Credential Access", "T1003.001 LSASS Memory"),
    # Saving the password databases from the registry: "reg save HKLM\SAM sam.hiv"
    rule(r"\breg(\.exe)?\"?\s+(save|export)\s+\"?hklm\\(sam|security)\b",
         "copies the Windows password database (SAM/SECURITY)", "Credential Access",
         "T1003.002 Security Account Manager"),
    # Copying the domain password database: "ntdsutil "ac i ntds" "ifm" "create full C:\x""
    rule(r"\bntdsutil(\.exe)?\b.*\b(ifm|create full)\b", "copies the domain password database (NTDS)",
         "Credential Access", "T1003.003 NTDS"),
]


def check_credential_theft(events, context):
    """Strong: stealing saved passwords (browser stores, LSASS dumps, SAM/NTDS copies).
    A browser reading its own files is skipped."""
    return check_by_rules(events, "credential_theft", "Saved passwords stolen", "Strong",
                          CREDENTIAL_THEFT_RULES, skip_programs=BROWSERS)
