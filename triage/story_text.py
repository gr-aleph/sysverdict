"""The words of the story: MITRE ATT&CK tags and one plain sentence per check."""




CONFIDENCE = {"Strong": "High", "Weak": "Low"}


# MITRE ATT&CK tag per check: (tactic, technique).
ATTACK_TAGS = {
    "document_app_spawns_program": ("Execution", "T1204.002 User Execution: Malicious File"),
    "suspicious_powershell": ("Execution", "T1059.001 PowerShell"),
    "lsass_access": ("Credential Access", "T1003.001 LSASS Memory"),
    "recon_burst": ("Discovery", "T1033 System Owner/User Discovery"),
    "masquerading": ("Defense Evasion", "T1036 Masquerading"),
    "lookalike_domain": ("Command and Control", "T1071.001 Web Protocols"),
    "persistence_run_key": ("Persistence", "T1547.001 Registry Run Keys"),
    "persistence_service": ("Persistence", "T1543.003 Windows Service"),
    "ransom_note": ("Impact", "T1486 Data Encrypted for Impact"),
    "run_from_user_folder": ("Execution", "T1204.002 User Execution: Malicious File"),
    "network_from_user_folder": ("Command and Control", "T1071.001 Web Protocols"),
    "dll_from_user_folder": ("Defense Evasion", "T1218.011 Rundll32"),
    "script_host_online": ("Command and Control", "T1105 Ingress Tool Transfer"),
    "remote_access_tool": ("Command and Control", "T1219 Remote Access Software"),
    "web_shell": ("Persistence", "T1505.003 Web Shell"),
    "archive": ("Collection", "T1560.001 Archive via Utility"),
    "copy_to_other_drive": ("Exfiltration", "T1052.001 Exfiltration over USB"),
    "cloud_upload": ("Exfiltration", "T1567.002 Exfiltration to Cloud Storage"),
    # The command-line checks below carry the exact tag of the rule that matched (see checks_rules.py);
    # these are only the defaults.
    "remote_execution": ("Lateral Movement", "T1021 Remote Services"),
    "access_change": ("Persistence", "T1098 Account Manipulation"),
    "scheduled_task": ("Persistence", "T1053.005 Scheduled Task"),
    "tool_download": ("Command and Control", "T1105 Ingress Tool Transfer"),
    "credential_theft": ("Credential Access", "T1555 Credentials from Password Stores"),
    "evidence_removal": ("Defense Evasion", "T1070 Indicator Removal"),
    "defender_weakened": ("Defense Evasion", "T1562.001 Disable or Modify Tools"),
    "uac_bypass": ("Privilege Escalation", "T1548.002 Bypass User Account Control"),
}


# A recon burst is tagged by the discovery tool that ran first (other tools: T1033 above).
RECON_TECHNIQUES = {
    "whoami.exe": "T1033 System Owner/User Discovery",
    "quser.exe": "T1033 System Owner/User Discovery",
    "ipconfig.exe": "T1016 System Network Configuration Discovery",
    "route.exe": "T1016 System Network Configuration Discovery",
    "arp.exe": "T1016 System Network Configuration Discovery",
    "nslookup.exe": "T1016 System Network Configuration Discovery",
    "netstat.exe": "T1049 System Network Connections Discovery",
    "systeminfo.exe": "T1082 System Information Discovery",
    "hostname.exe": "T1082 System Information Discovery",
    "net.exe": "T1087 Account Discovery",
    "net1.exe": "T1087 Account Discovery",
    "nltest.exe": "T1087 Account Discovery",
    "tasklist.exe": "T1057 Process Discovery",
}


# One plain sentence per check. {detail} and {process} come from the finding.
SENTENCES = {
    "document_app_spawns_program": "A document program started another program ({detail}). Documents "
                                   "should not start programs: this is how a malicious document runs its payload.",
    "suspicious_powershell": "PowerShell downloaded code, ran text as code or decoded hidden code ({detail}).",
    "lsass_access": "{detail}. LSASS holds Windows passwords, so this is a sign of credential theft.",
    "recon_burst": "{detail}: discovery commands that malware runs to learn who the user is and what "
                   "the network looks like.",
    "masquerading": "A disguised program appeared: {detail}.",
    "lookalike_domain": "{process} looked up a lookalike domain: {detail}.",
    "persistence_run_key": "{process} added itself to the Run key, so it starts again at every logon.",
    "persistence_service": "A Windows service was created that runs a file dropped during the attack "
                           "({detail}), so it starts again at every boot, with full rights.",
    "ransom_note": "A possible ransom note was opened ({detail}). Treat this as a ransomware incident.",
    "run_from_user_folder": "{detail}.",
    "network_from_user_folder": "{detail}, a server on the internet (possible command and control).",
    "remote_execution": "{detail}. Admins do this, but so do attackers spreading to other computers.",
    "access_change": "{detail}. Admins do this, but so do attackers keeping a way back in.",
    "scheduled_task": "{detail}. A task runs again later, so it can also keep malware running.",
    "tool_download": "{detail}. This Windows program is not a download tool, a known way to bring in malware.",
    "dll_from_user_folder": "{detail}: a DLL started from a folder any user can write to.",
    "script_host_online": "{detail}: a script program talking to the internet itself, as download "
                          "commands and remote-control malware do.",
    "remote_access_tool": "{detail}. Help desks use these tools, and so do attackers who talk a user "
                          "into installing one.",
    "web_shell": "{detail}. A web or database server should never open a command prompt: this is how a "
                 "web shell (an attacker's script on the website) runs commands.",
    "archive": "{detail}. Packing files is how data is collected before it is taken out.",
    "copy_to_other_drive": "{detail}: possibly a USB stick or network drive used to take data out.",
    "cloud_upload": "{detail}: a service often used to upload stolen data.",
    "credential_theft": "{detail}. This steals saved passwords: treat every account used on this computer "
                        "as known to the attacker.",
    "evidence_removal": "{detail}. Attackers do this to hide what they did or to stop recovery.",
    "defender_weakened": "{detail}. This lets malware run without Microsoft Defender seeing it.",
    "uac_bypass": "{detail}. This gives a program admin rights without the Windows prompt.",
}
