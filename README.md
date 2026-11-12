# SysVerdict

Sysmon log triage for SOC teams. Upload a Sysmon `.evtx` log and get a verdict (Malicious,
Suspicious or Benign), the attack story with MITRE ATT&CK tags, next steps grouped by NIST incident
response phase, IOCs and a process tree. Every claim links to the raw events behind it.

Logs are processed locally. Offline mode is on by default; when it is off, only hashes, public IPv4
addresses and public domains are sent, and only to the local enrichment backends. See [design.md](design.md).

## Install

Requires Windows and Python 3.14.

```bat
py -3.14 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

## Run

```bat
.venv\Scripts\python -m streamlit run app.py
```

Open the address Streamlit prints and upload a log, for example one exported with
`wevtutil epl Microsoft-Windows-Sysmon/Operational host.evtx`.

**With enrichment:** install [hash-enrich-2](https://github.com/gr-aleph/hash-enrich-2),
[enrichment-portal-simple](https://github.com/Bed-e/enrichment-portal-simple) and
[ioc-simple-dns](https://github.com/NewCooDooer/ioc-simple-dns) side by side in an `enrichment-backends`
folder next to this one (each per its own README), then run `start.cmd`. It starts the backends and the
app; a backend that is missing shows as not running and its IOCs as not enriched.

## Test

```bat
.venv\Scripts\python -m pytest
```

Tests run offline with synthetic events and recorded backend responses; no network or API keys needed.
Real logs placed in the git-ignored `samples/` folder are also checked when present.
