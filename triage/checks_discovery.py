"""Checks for ATT&CK Discovery and Lateral Movement: recon bursts and commands run
on other computers."""

from triage.checks_common import PASS_ON_SHELLS, RECON_TOOLS, add_finding, events_of, file_name
from triage.checks_rules import check_by_rules, rule
from triage.parse import to_datetime


# Programs that mean "a person at the keyboard": the desktop, a remote admin session over
# WinRM (wsmprovhost.exe hosts PowerShell remoting), and the windows people type commands in
# (Windows Terminal, the PowerShell ISE, VS Code's terminal). Recon typed by a person is normal
# help-desk work.
PERSON_PROGRAMS = {"explorer.exe", "wsmprovhost.exe", "windowsterminal.exe", "powershell_ise.exe", "code.exe"}


def find_launcher(event, processes):
    """Who really started this command? Walk up past every 'cmd /c' or PowerShell in between
    (e.g. agent -> cmd -> powershell -> whoami gives the agent). If a shell's own start is not in
    the log (it was opened before the log began), the shell itself is returned."""
    guid, image = event.get("ParentProcessGuid", ""), event.get("ParentImage", "")
    for _ in range(10):  # 10 shells inside each other is already far more than real life
        if file_name(image) not in PASS_ON_SHELLS:
            break
        parent = processes.get(guid)
        if not parent:
            break  # the shell started before the log: we cannot see who opened it
        guid, image = parent.get("ParentProcessGuid", ""), parent.get("ParentImage", "")
    return guid, image


def check_recon_burst(events, context):
    """Strong: one program runs 2+ different discovery tools (whoami, ipconfig, ...) within 60 s.
    ATT&CK Discovery (T1033, T1016, T1082). Why 60 s and 2 tools: a person pauses to read each
    answer, a script runs its tools within seconds; 60 s is a generous window for that.
    Dual-use: admin and monitoring (RMM) tools run the same commands, so apply_dual_use_gate
    keeps it Strong only when the program has another high-confidence sign."""
    by_launcher = {}
    for e in events_of(events, 1):
        if file_name(e.get("Image")) in RECON_TOOLS:
            guid, image = find_launcher(e, context["processes"])
            if file_name(image) in PERSON_PROGRAMS:
                continue  # a person typing (locally or in a remote admin session), not a program
            if file_name(image) in PASS_ON_SHELLS:
                continue  # a shell opened before the log began: most likely a person's window
            by_launcher.setdefault((guid, image), []).append(e)

    found = {}
    for (guid, image), runs in by_launcher.items():
        for first in runs:
            start = to_datetime(first["time"])
            window = [r for r in runs if 0 <= (to_datetime(r["time"]) - start).total_seconds() <= 60]
            tools = sorted({file_name(r.get("Image")) for r in window})
            if len(tools) >= 2:
                for r in window:
                    if guid in found and r["record_id"] in found[guid]["event_ids"]:
                        continue
                    add_finding(found, guid, r, "recon_burst", "Reconnaissance commands in a burst",
                                "Strong", image, f"{file_name(image)} ran {', '.join(tools)} "
                                "within 60 seconds", guid)
    return list(found.values())


# Running commands on another computer. Admins do this every day, so these are Weak.
REMOTE_EXECUTION_RULES = [
    # PsExec / PaExec followed by a computer: "PsExec64.exe \\SRV-01 cmd"
    rule(r"\b(ps|pa)exec(64)?(\.exe)?\"?\s.*\\\\[a-z0-9._-]+", "runs a program on another computer with PsExec",
         "Lateral Movement", "T1021.002 SMB/Windows Admin Shares"),
    # WMI on another computer: "wmic /node:SRV-01 process call create ..."
    rule(r"\bwmic(\.exe)?\b.*\s/node:", "runs a command on another computer with WMI",
         "Execution", "T1047 Windows Management Instrumentation"),
    # Windows Remote Shell: "winrs -r:SRV-01 cmd"
    rule(r"\bwinrs(\.exe)?\b.*\s[-/]r(emote)?:", "runs a command on another computer with WinRS",
         "Lateral Movement", "T1021.006 Windows Remote Management"),
    # PowerShell remoting: Invoke-Command -ComputerName ..., Enter-PSSession, New-PSSession
    rule(r"invoke-command\b.*-computername|enter-pssession|new-pssession",
         "runs PowerShell on another computer", "Lateral Movement", "T1021.006 Windows Remote Management"),
    # A scheduled task or service on another computer: "schtasks /create /s SRV-01 ...", "sc \\SRV-01 create"
    rule(r"\bschtasks(\.exe)?\b.*\s/s\s+\S", "creates or changes a scheduled task on another computer",
         "Lateral Movement", "T1053.005 Scheduled Task"),
    rule(r"\bsc(\.exe)?\"?\s+\\\\[a-z0-9._-]+", "creates or changes a service on another computer",
         "Lateral Movement", "T1569.002 Service Execution"),
    # An admin share: \\SRV-01\C$ or \\SRV-01\ADMIN$ (copying tools there, or "net use" to it)
    rule(r"\\\\[a-z0-9._-]+\\([a-z]|admin)\$", "uses an administrative share on another computer",
         "Lateral Movement", "T1570 Lateral Tool Transfer"),
]


def check_remote_execution(events, context):
    """Weak: a command run on another computer (PsExec, WMI, WinRS, remoting, admin shares)."""
    return check_by_rules(events, "remote_execution", "Command run on another computer", "Weak",
                          REMOTE_EXECUTION_RULES)
