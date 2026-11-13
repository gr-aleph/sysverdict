"""The dual-use gate: a High finding for an action with a common legitimate use stays
High only when something backs it up (rules 1-4 below); otherwise it becomes Low."""

from triage.checks_common import SERVICE_TITLE, file_name, in_user_folder


# Some Strong behaviours also have a common legitimate version: recon by an admin or monitoring
# (RMM) tool, a security product reading LSASS, a lookalike-looking domain, an install script that
# downloads and runs code, a new service. On its own such a finding is Low. It stays High when:
#   1. the program itself or the program that started it runs from a user folder: admin and RMM
#      tools are installed in Program Files. The program that WROTE its file counts here only
#      when the analyst says IT installs all software (a sidebar switch): where users install
#      their own software, a setup program in Downloads is how normal tools arrive; or
#   2. that chain program is a proxy host (rundll32, regsvr32, mshta: ATT&CK T1218, "System
#      Binary Proxy Execution"), which admins do not use to run commands; or
#   3. a High finding that is NOT dual-use shares a program with its chain (e.g. the same
#      program also deleted backups); or
#   4. a High finding of a DIFFERENT dual-use kind shares a program with its chain (e.g. recon
#      plus download-and-run, or recon plus an LSASS read): two different steps of an attack
#      in one chain are a coherent story, not one ambiguous action. (Two findings of the same
#      kind, e.g. two recon bursts, do not count.)
# Never dual-use (High on their own): disguised programs, ransom notes, stolen passwords,
# logs/backups deleted, UAC bypass, a document starting a shell.
DUAL_USE_CHECKS = {"recon_burst", "lookalike_domain", "suspicious_powershell", "lsass_access"}


PROXY_HOSTS = {"rundll32.exe", "regsvr32.exe", "mshta.exe"}


def is_dual_use(finding):
    return finding["check"] in DUAL_USE_CHECKS or finding["title"] == SERVICE_TITLE


def kind_of(finding):
    """What kind of action a finding is: its check, or its title for the two kinds of persistence."""
    return finding["title"] if finding["check"] == "persistence" else finding["check"]


def chain_of(finding, context):
    """ProcessGuid -> program path for the finding's program, the program that started it and
    the program that created its file (when they are in the log)."""
    chain = {finding["process_guid"]: finding["process"]}
    started = context["processes"].get(finding["process_guid"])
    if started:
        chain[started.get("ParentProcessGuid", "")] = started.get("ParentImage", "")
    creator = context["file_creators"].get(finding["process"].lower(), "")
    if creator in context["processes"]:
        chain[creator] = context["processes"][creator].get("Image", "")
    chain.pop("", None)
    return chain


def apply_dual_use_gate(findings, context):
    """Turn a dual-use Strong finding into Weak when nothing backs it up (rules 1-3 above)."""
    to_lower = []
    for f in findings:
        if f["strength"] != "Strong" or not is_dual_use(f):
            continue
        chain = chain_of(f, context)
        # The running programs: the finding's own program and the program that started it.
        started = context["processes"].get(f["process_guid"], {})
        programs = [f["process"], started.get("ParentImage", "")]
        if context["it_installs_all"]:
            programs += list(chain.values())  # also the program that wrote its file
        if any(in_user_folder(p) or file_name(p) in PROXY_HOSTS for p in programs):
            continue  # rules 1 and 2
        backed = False
        for other in findings:
            if other is f or other["strength"] != "Strong":
                continue
            if not set(chain) & set(chain_of(other, context)):
                continue  # not in the same process chain
            if not is_dual_use(other):
                backed = True  # rule 3
            elif kind_of(other) != kind_of(f):
                backed = True  # rule 4
        if not backed:
            to_lower.append(f)
    # Changed only after all were decided, so the order of the findings does not matter.
    for f in to_lower:
        f["strength"] = "Weak"
        f["detail"] += " (dual-use: no other high-confidence sign on this program)"
