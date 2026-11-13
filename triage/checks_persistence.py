"""Checks for ATT&CK Persistence: Run keys, services, scheduled tasks, new accounts
and firewall changes."""

import re

from triage.checks_common import (SERVICE_TITLE, SHELLS, add_finding, events_of, file_name, full_windows_path,
                                  in_user_folder, is_known_good)
from triage.checks_rules import check_by_rules, rule


def check_persistence(events, context):
    """Strong: a Run key that starts a user-folder DLL with rundll32/regsvr32, or a service whose
    program is in a user folder or was dropped during this log outside Program Files.
    Weak: a Run key that starts a program from a user folder (tray apps do this too)."""
    found = {}
    for e in events_of(events, 13):
        target = e.get("TargetObject", "")
        value = e.get("Details", "")
        writer = e.get("Image", "")
        # The program the key will start, without quotes and arguments.
        value_path = value.strip('"').split('"')[0].lower()
        value_path = value_path.split(".exe")[0] + ".exe" if ".exe" in value_path else value_path
        value_path = full_windows_path(value_path)

        # A Run or RunOnce registry key, e.g. ...\Microsoft\Windows\CurrentVersion\Run\FireEye.
        # (\\ is one backslash; (once)? means "Once" may follow "Run".)
        if re.search(r"\\currentversion\\run(once)?\\", target, re.IGNORECASE):
            detail = f"{file_name(writer)} set {target.split(chr(92))[-1]} = {value[:150]}"
            # rundll32/regsvr32 starting a DLL from a user folder at every logon: no common
            # legitimate use, so Strong. A program in a user folder: tray apps (Discord, Zoom)
            # do this too, so Weak.
            starts_user_dll = (file_name(value_path) in ("rundll32.exe", "regsvr32.exe")
                               and ".dll" in value.lower() and in_user_folder(value))
            if starts_user_dll:
                add_finding(found, target.lower(), e, "persistence", "Starts a DLL at logon (Run key)",
                            "Strong", writer, detail, e.get("ProcessGuid", ""))
            elif in_user_folder(writer) or in_user_folder(value_path):
                add_finding(found, target.lower(), e, "persistence", "Starts itself at logon (Run key)",
                            "Weak", writer, detail, e.get("ProcessGuid", ""))
            # Any other new Run key entry is worth a look too (ATT&CK T1547.001), except a known-good
            # program, or an installed program adding ITSELF (Edge, Teams and tray apps do this).
            elif not is_known_good(value_path) and file_name(writer) != file_name(value_path):
                add_finding(found, target.lower(), e, "persistence", "New program set to start at logon",
                            "Weak", writer, detail, e.get("ProcessGuid", ""))
        # The program path of a Windows service: ...\Services\<service name>\ImagePath.
        # ([^\\]+ is the service name: one or more characters that are not a backslash.)
        elif re.search(r"\\services\\[^\\]+\\imagepath$", target, re.IGNORECASE):
            # Real installers put service programs in Program Files; malware often uses
            # System32 or a user folder.
            dropped = value_path in context["dropped_files"]
            in_program_files = "\\program files" in value_path
            # Defender platform updates (known-good list) and driver updates (Windows installs
            # drivers from its DriverStore) create new service files all the time.
            if is_known_good(value_path) or "\\windows\\system32\\driverstore\\" in value_path:
                continue
            service = target.split("\\")[-2]
            # Point at the service program itself (not services.exe, which wrote the key).
            guid = next((p["ProcessGuid"] for p in context["processes"].values()
                         if p.get("Image", "").lower() == value_path), "")
            if (dropped and not in_program_files) or in_user_folder(value_path):
                add_finding(found, target.lower(), e, "persistence", SERVICE_TITLE,
                            "Strong", value_path, f"service '{service}' runs {value[:150]}, a file "
                            "created during this log", guid)
            # Any other new or changed service is worth a look too (ATT&CK T1543.003), except one in
            # the Windows folder (Windows updates rewrite those all the time). A service that runs a
            # shell (cmd /c ..., %COMSPEC%, powershell) is the PsExec / attack-tool pattern
            # (T1569.002), so it is reported even though cmd.exe lives in the Windows folder.
            elif (not value_path.startswith("c:\\windows\\") or file_name(value_path) in SHELLS
                  or "%comspec%" in value.lower()):
                add_finding(found, target.lower(), e, "persistence", "New or changed service",
                            "Weak", value_path or value, f"service '{service}' runs {value[:150]}", guid)
    return list(found.values())


# Creating accounts, giving admin rights, opening the firewall. Admins do this too: Weak.
ACCESS_CHANGE_RULES = [
    # "net user helpdesk **** /add" (net1.exe is the same tool)
    rule(r"\bnet1?(\.exe)?\"?\s+user\s+\S+.*\s/add\b", "creates a user account",
         "Persistence", "T1136.001 Local Account"),
    # "net localgroup Administrators helpdesk /add", also Domain Admins and Remote Desktop Users
    rule(r"\bnet1?(\.exe)?\"?\s+(localgroup|group)\s+\"?(administrators|domain admins|enterprise admins|"
         r"remote desktop users)\"?\s+\S+.*\s/add\b", "adds an account to a privileged group",
         "Persistence", "T1098 Account Manipulation"),
    # The same with PowerShell: New-LocalUser, Add-LocalGroupMember -Group Administrators
    rule(r"new-localuser\b", "creates a user account", "Persistence", "T1136.001 Local Account"),
    rule(r"add-localgroupmember\b.*(administrators|remote desktop users)", "adds an account to a privileged group",
         "Persistence", "T1098 Account Manipulation"),
    # "netsh advfirewall firewall set rule ... enable=yes", "netsh firewall add ..."
    rule(r"\bnetsh(\.exe)?\b.*\bfirewall\b.*\b(add|set|delete)\b", "changes the Windows firewall",
         "Defense Evasion", "T1562.004 Disable or Modify System Firewall"),
]


# A new scheduled task (it runs again later, often as SYSTEM). Many admin and update tools do
# this too: Weak.
SCHEDULED_TASK_RULES = [
    rule(r"\bschtasks(\.exe)?\b.*\s/create\b", "creates a scheduled task", "Persistence", "T1053.005 Scheduled Task"),
    rule(r"register-scheduledtask\b", "creates a scheduled task", "Persistence", "T1053.005 Scheduled Task"),
]


def check_access_change(events, context):
    """Weak: a new account, an account added to an admin group, or a firewall change."""
    return check_by_rules(events, "access_change", "Account or firewall change", "Weak", ACCESS_CHANGE_RULES)


def check_scheduled_task(events, context):
    """Weak: a scheduled task was created."""
    return check_by_rules(events, "scheduled_task", "Scheduled task created", "Weak", SCHEDULED_TASK_RULES)
