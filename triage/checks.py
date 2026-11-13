"""The detection checks and the verdict.

Each check is one small function that looks at the events and returns a list of findings.
A finding is a plain dict:

    {"check": "recon_burst",                    # which check fired
     "title": "Reconnaissance commands in a burst",
     "strength": "Strong",                      # "Strong" or "Weak"
     "time": "2023-12-13 10:53:39.908",         # first matching event (UTC)
     "process": "C:\\...\\FireEye.exe",         # the program that did it
     "process_guid": "{...}",                   # used to colour the attack map
     "detail": "ran whoami.exe, ipconfig.exe within 60 seconds",
     "event_ids": [16890, 16893]}               # record IDs of the proof

The verdict comes only from the findings (and optionally enrichment), so the same log
always gives the same answer, and every answer can be traced to its events.

Where the checks live (one file per ATT&CK tactic):
    checks_execution.py, checks_persistence.py, checks_credentials.py, checks_evasion.py,
    checks_discovery.py, checks_c2.py, checks_exfil.py  - the checks themselves
    checks_rules.py   - the engine for the command-line rule lists
    checks_gate.py    - the dual-use gate (ambiguous High findings need backup)
    checks_common.py  - shared lists and small helpers
This file runs them all and turns the findings into a verdict.
"""

from triage.checks_c2 import (check_lookalike_domain, check_network_from_user_folder, check_remote_access_tool,
                              check_script_host_online, check_tool_download)
from triage.checks_common import events_of
from triage.checks_credentials import check_credential_theft, check_lsass_access
from triage.checks_discovery import check_recon_burst, check_remote_execution
from triage.checks_evasion import (check_defender_weakened, check_dll_from_user_folder, check_evidence_removal,
                                   check_masquerading, check_uac_bypass)
from triage.checks_execution import (check_document_app_spawns_program, check_run_from_user_folder,
                                     check_suspicious_powershell, check_web_shell)
from triage.checks_exfil import check_archive, check_cloud_upload, check_copy_to_other_drive, check_ransom_note
from triage.checks_gate import apply_dual_use_gate
from triage.checks_persistence import check_access_change, check_persistence, check_scheduled_task

# Every check, in the order they run (the order findings with the same time are listed in).
ALL_CHECKS = [
    check_document_app_spawns_program,
    check_suspicious_powershell,
    check_lsass_access,
    check_recon_burst,
    check_masquerading,
    check_lookalike_domain,
    check_persistence,
    check_ransom_note,
    check_run_from_user_folder,
    check_network_from_user_folder,
    check_script_host_online,
    check_remote_access_tool,
    check_web_shell,
    check_archive,
    check_copy_to_other_drive,
    check_cloud_upload,
    check_remote_execution,
    check_access_change,
    check_scheduled_task,
    check_tool_download,
    check_dll_from_user_folder,
    check_credential_theft,
    check_evidence_removal,
    check_defender_weakened,
    check_uac_bypass,
]


def run_checks(events, it_installs_all=False):
    """Run every check and return all findings, oldest first.
    it_installs_all: True when IT installs all software on this client (users never do), so a
    program installed from a user folder is itself a warning sign (see the dual-use gate)."""
    context = {
        "it_installs_all": it_installs_all,
        # ProcessGuid -> its process-creation event, to look up parents.
        "processes": {e["ProcessGuid"]: e for e in events_of(events, 1) if e.get("ProcessGuid")},
        # Every file created during the log (lowercase paths).
        "dropped_files": {e.get("TargetFilename", "").lower() for e in events_of(events, 11)},
        # Created file (lowercase path) -> the ProcessGuid of the program that wrote it.
        "file_creators": {e.get("TargetFilename", "").lower(): e.get("ProcessGuid", "")
                          for e in events_of(events, 11)},
    }
    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(events, context))
    apply_dual_use_gate(findings, context)
    findings.sort(key=lambda f: f["time"])
    return findings


def make_verdict(findings, enrichment_verdicts=()):
    """Malicious / Suspicious / Benign, with one sentence saying why.

    enrichment_verdicts is a list of "malicious" / "suspicious" / other words from the backends.
    """
    strong = [f for f in findings if f["strength"] == "Strong"]
    weak = [f for f in findings if f["strength"] == "Weak"]
    enrichment_verdicts = [v.lower() for v in enrichment_verdicts]

    if strong:
        names = sorted({f["title"] for f in strong})
        return {"label": "Malicious", "reason": f"{len(strong)} high-confidence finding(s): " + "; ".join(names)}
    if "malicious" in enrichment_verdicts:
        return {"label": "Malicious", "reason": "an enrichment source rates an indicator as malicious"}
    if weak:
        return {"label": "Suspicious", "reason": f"{len(weak)} low-confidence finding(s) worth a look, "
                                                 "none high-confidence on its own"}
    if "suspicious" in enrichment_verdicts:
        return {"label": "Suspicious", "reason": "an enrichment source rates an indicator as suspicious"}
    return {"label": "Benign", "reason": "no known-bad activity found by any check"}
