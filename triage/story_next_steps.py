"""Next steps grouped by NIST SP 800-61 incident-response phase."""

import re


PHASES = ["Investigate", "Contain", "Eradicate", "Recover"]  # NIST SP 800-61 incident response


ACTIONS = {
    "ransom_note": [("Contain", "Disconnect the computer from the network now; do not shut it down "
                                "(memory holds evidence)."),
                    ("Investigate", "Find which files were encrypted and whether data was copied out first."),
                    ("Eradicate", "Rebuild the computer from a known-good image instead of cleaning it."),
                    ("Recover", "Restore files from offline backups after checking the backups are clean.")],
    "lsass_access": [("Contain", "Reset the passwords of every account that logged on to this computer, "
                                 "admins first."),
                     ("Investigate", "Check where those accounts logged on after the LSASS access.")],
    "recon_burst": [("Contain", "Isolate the computer: the malware ran and probably reported back."),
                    ("Investigate", "Check what the same program did after the discovery commands.")],
    "persistence": [("Eradicate", "Remove the Run key or service listed under IOCs, reboot, and confirm "
                                  "it does not come back."),
                    ("Investigate", "Search other computers for the same Run key or service name.")],
    "document_app_spawns_program": [("Investigate", "Find where the document came from (see IOCs) and "
                                                    "search mailboxes and other computers for it."),
                                    ("Eradicate", "Delete the document and every file it dropped.")],
    "masquerading": [("Investigate", "Collect the disguised file for analysis and search other computers "
                                     "for its SHA256."),
                     ("Eradicate", "Delete the disguised file and all its copies.")],
    "suspicious_powershell": [("Investigate", "Check what the PowerShell command downloaded (see the decoded "
                                              "command under Findings) and whether it ran.")],
    "lookalike_domain": [("Contain", "Block the lookalike domain at the DNS filter or web proxy."),
                         ("Investigate", "Search DNS and proxy logs for other computers that visited it.")],
    "network_from_user_folder": [("Contain", "Block the attacker IPs listed under IOCs at the firewall.")],
    "run_from_user_folder": [("Investigate", "Ask the user whether they installed the programs listed "
                                             "under Findings.")],
    "remote_execution": [("Investigate", "Ask the admin whether the remote commands were planned (change "
                                         "ticket), and check the other computers for what ran there.")],
    "access_change": [("Investigate", "Confirm the new or changed accounts and firewall rules with IT; "
                                      "remove any nobody asked for.")],
    "scheduled_task": [("Investigate", "Check what the new scheduled task runs and who created it.")],
    "tool_download": [("Investigate", "Find the downloaded file (see the command under Findings), get its "
                                      "SHA256 and check its reputation.")],
    "dll_from_user_folder": [("Investigate", "Collect the DLL listed under Findings and check its SHA256 "
                                             "and signature.")],
    "script_host_online": [("Investigate", "Check what the script program downloaded or sent (see the "
                                           "command under Findings) and the reputation of the IP.")],
    "remote_access_tool": [("Investigate", "Ask the user and the help desk whether a support session was "
                                           "planned (a ticket); if not, remove the tool and treat it as "
                                           "an intrusion.")],
    "web_shell": [("Contain", "Take the website offline or block outside access to it until it is cleaned."),
                  ("Eradicate", "Find and delete the web shell file in the website folder (compare it with "
                                "a clean copy), and patch the hole it came in through.")],
    "archive": [("Investigate", "Find the archive named under Findings: what was packed, and where did it go?")],
    "copy_to_other_drive": [("Investigate", "Ask who copied the files to that drive and why; check the "
                                            "company's rules on USB sticks.")],
    "cloud_upload": [("Investigate", "Check the proxy or firewall logs for how much data was uploaded to "
                                     "the service named under Findings.")],
    "credential_theft": [("Contain", "Reset the passwords of every account used on this computer, and "
                                     "sign them out of websites (stolen cookies stay valid until then)."),
                         ("Investigate", "Check where those accounts signed in after the theft.")],
    "evidence_removal": [("Contain", "Isolate the computer: someone is hiding their tracks."),
                         ("Investigate", "Collect logs from your SIEM or other computers for the time the "
                                         "local logs were cleared or Sysmon was off."),
                         ("Recover", "Restore from offline backups if shadow copies or backups were deleted.")],
    "defender_weakened": [("Investigate", "Check whether IT made the Defender change on purpose; otherwise "
                                          "undo it and scan the excluded folder.")],
    "uac_bypass": [("Eradicate", "Delete the UAC-bypass registry key and the program it starts."),
                   ("Investigate", "Check what ran with admin rights after the bypass.")],
}


def next_steps(findings, verdict, steps=()):
    """Return {"Investigate": [...], "Contain": [...], "Eradicate": [...], "Recover": [...]} (no empty phases)."""
    plan = {phase: [] for phase in PHASES}

    def add(phase, text):
        if text not in plan[phase] and len(plan[phase]) < 4:
            plan[phase].append(text)

    if verdict["label"] == "Benign":
        add("Investigate", "Nothing known-bad was found by the checks; this does not prove the "
                           "computer is clean. Keep this result with the ticket.")
        add("Investigate", "If the user still reports a problem, collect a longer log and run it again.")
    else:
        strong_checks = {f["check"] for f in findings if f["strength"] == "Strong"}
        fired = strong_checks or {f["check"] for f in findings}
        for check, actions in ACTIONS.items():
            if check in fired:
                for phase, text in actions:
                    add(phase, text)
        for step in steps:
            # The host of the download address: the characters after "://" up to the first
            # "/", space, comma, quote or bracket ([^...]+ = one or more characters NOT in the list),
            # so "https://a.com, from the page ..." gives "a.com".
            found = re.search(r"://([^/\s,;'\"()`]+)", step["text"]) if step.get("kind") == "origin" else None
            if found:
                add("Contain", f"Block the download site {found.group(1)} at the web proxy.")
            if step.get("technique", "").startswith("T1566.001"):
                add("Investigate", "Find the email and remove it from every mailbox.")
        if verdict["label"] == "Malicious":
            add("Investigate", "Add the IOCs to the ticket and look for them in your EDR, proxy and email logs.")
            add("Recover", "Return the computer to service only after a clean scan and a day of monitoring.")
        else:
            add("Investigate", "If the user did not expect these programs, treat the computer as compromised.")
    return {phase: items for phase, items in plan.items() if items}
