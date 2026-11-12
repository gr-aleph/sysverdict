# SysVerdict: design

## Purpose

SysVerdict is for a SOC or MSP analyst who receives a Sysmon log from a Windows computer and must decide
quickly whether an incident happened, what it was, and what to do next. Triage here means that first
decision, not the full investigation: a verdict, the evidence for it, the attack story, next steps and IOCs.
"Benign" means no check found known-bad activity; it is never presented as proof the computer is clean.

## Architecture

```
 Browser -> Streamlit app (app.py, 127.0.0.1)
              triage/parse.py     .evtx -> event dicts
              triage/checks.py    detection checks -> findings -> verdict
              triage/story.py     delivery, attack steps, ATT&CK tags, NIST next steps
              triage/iocs.py      IOCs of flagged programs + privacy filter
              triage/graph.py     process tree
              triage/timeline.py, domains.py
              triage/enrich.py ──HTTP──> hash / IP / DNS backends (127.0.0.1) ──> public threat-intel sources
```

- **Where the log goes:** it stays on this computer. The evtx reader reads a file, so a temporary copy is
  written to the Windows Temp folder, read, and deleted right after parsing (also when parsing fails); the
  results are kept in memory while the app runs. Nothing is stored. CSV and JSON files exist only when the analyst downloads them.
- **What leaves the machine:** nothing in offline mode (the default). Otherwise, only after the analyst presses
  *Enrich IOCs*: SHA256 hashes, public IPv4 addresses and public domains of flagged programs, sent to the local
  backends. Raw events, usernames, hostnames, paths, registry keys, private IPs, IPv6 and internal names are
  never sent (`check_shareable` in `triage/iocs.py`). Neither are the organisation's own domains: the DNS
  suffix of each full computer name in the log (pc01.contoso.com -> contoso.com) and its subdomains.
- **No third-party loading:** Streamlit telemetry is off, fonts are bundled, and the process tree is plain HTML/CSS
  with no external JavaScript.

## Backend API contract

| Backend | Request | Fields read | Failure handling |
| --- | --- | --- | --- |
| hash-enrich-2 | `GET /api/v1/hash/{sha256}`, health `GET /api/v1/health` | `verdict.label`, `verdict.score`, `verdict.reasons`, `verdict.failed_sources` | non-200 or missing `verdict` -> not enriched |
| enrichment-portal-simple | `GET /api/ip/{ipv4}`; no health route, so any answer to `GET /api/ip/` means running | `verdict.level`, `verdict.score`, `verdict.summary` | 503 -> sources unavailable; `not_applicable` -> not judged |
| ioc-simple-dns | `GET /api/v1/domain/{name}`, health `GET /api/v1/health` | `assessment.verdict`, `assessment.verdict_label`, `assessment.average` | `not_graded` -> not enriched |

Connection errors, timeouts, non-JSON replies and answers with an unexpected shape always become "not enriched" with a reason; they never stop the page.

## Decisions

- **Streamlit:** the rest of the tool is Python, and Streamlit gives a local, private web app in the same
  language with upload, tabs and export built in, so the effort goes into the detection logic.
- **Verdict from named findings, not a numeric score:** a list of findings with their events tells the analyst what to do and can be verified.
- **High or low confidence by one question: does the action have a common legitimate use?** No (password theft, download-and-run, clearing logs, UAC bypass) = high = Malicious; yes (admin tools, new accounts, Run keys, Windows-tool downloads) = low = Suspicious, however many there are.
- **Checks come from gaps in ATT&CK tactic coverage, not from sample logs:** test logs are only used afterwards as an exam, so the rules are not tuned to them.
- **Actions are judged by what they do, not by who typed them:** an attacker with a stolen admin account types the same commands as the admin.
- **Encoded PowerShell is decoded and judged by its content:** monitoring agents encode commands too; encoding alone is not a finding.
- **Short, readable checks:** each check is one function (or one list of commented patterns) that can be reviewed on its own; they target common attacker behaviour, not every technique.
- **Small known-good list (`data/known_good.txt`):** keeps common software in user folders from being flagged; kept short because each entry is a place malware could hide.
- **Services installed in Program Files are trusted:** legitimate installers create services there constantly; services dropped elsewhere are flagged.
- **Discovery commands typed by a person are ignored:** recon from the desktop, a terminal window or a remote admin session (WinRM) is normal help-desk work; recon started by a program is a finding.
- **Dual-use findings need backup to be high confidence:** recon, a lookalike lookup, download-and-run, an LSASS read or a new service also happen in normal IT work (RMM, security tools, installers), so on their own they are low; they stay high when the program (or the one that started it) runs from a user folder or a proxy host (rundll32, regsvr32, mshta), or shares its process chain with a high finding that has no legitimate use. Two dual-use findings never back each other up.
- **"IT installs all software" switch, off by default:** where users install their own software, a setup program in Downloads is how normal tools arrive, so it is not held against the installed tool; for clients where IT pushes everything, the analyst turns it on and a user-installed tool counts as a warning sign. Off is the safe side, because a false Malicious costs more than a Suspicious that an analyst reviews.
- **Generalization is tested, not assumed:** labelled logs the code was never written against are scored with `evaluate.py`, and a renaming test checks that each scenario gives the same verdict with other users, hosts, files, domains, IPs and times.
- **Delivery is reconstructed from the log, not guessed:** the browser download record, parent process and UAC prompt explain how the first file arrived; anything missing is stated as "not in this log", and no ATT&CK technique is claimed that the log cannot prove.
- **MITRE ATT&CK tags and NIST phases:** standard vocabulary analysts and their tools already use.
- **IOCs only for flagged programs:** keeps the list actionable and protects the enrichment sources' rate limits.
- **Enrichment on demand, capped per run and cached:** nothing leaves by accident, the free-tier limits of the sources are respected (caps in `enrich.py`), and errors are never cached.
- **Passwords are hidden as soon as an event is read:** no tab, export or raw-event view can show one.
- **Enrichment can raise the verdict, never lower it:** "no known bad" from a source is absence of evidence and does not cancel a finding.
- **Addresses are shown exactly but never as links:** the page renders URLs, domains and IPs as code text so nobody opens an attacker's site by accident.
- **An indented process tree, not a graph drawing:** a fixed layout cannot overlap and reads top to bottom like an EDR process view.
- **Domain labels are heuristics marked "likely":** Sysmon has no referrer, so visited sites and page resources are inferred from timing and a local ad/CDN list.
- **Templated explanations, no AI service:** no log data leaves the machine and the same log always gives the same text.
- **Times are UTC unless a zone is chosen:** UTC matches the raw log and other tools; local time replaces it on screen only.
- **No real logs in the repository:** they contain usernames, hostnames and SIDs; tests use synthetic events and recorded backend responses.
- **Plain functions and dicts:** every module is short and testable without a framework.

## Assumptions and limits

- Input is the `Microsoft-Windows-Sysmon/Operational` log as `.evtx`; other providers are ignored.
- One log covers one computer and one incident window; machine-to-machine movement is shown only as connections from this computer.
- Parents that started before the log began appear without details.
- The lookalike check covers only the brands in `data/brands.txt`.
- Not used yet: time of day (off-hours activity needs each client's working hours), file signatures
  (Sysmon event 7 is often not collected), and Windows Security logs.
