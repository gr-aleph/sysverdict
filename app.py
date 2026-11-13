"""SysVerdict: the Streamlit page.

Run with:  .venv\\Scripts\\python -m streamlit run app.py

Flow: upload a .evtx -> parse -> checks -> verdict -> story (steps with MITRE ATT&CK tags),
next steps (NIST phases), findings, IOCs, process tree, timeline, domains.
Enrichment is optional and off by default (offline mode).
This file is the page flow (sidebar, loading, verdict, tabs); each tab is drawn by a ui_*.py file.
"""

import hashlib
import os
import tempfile
from pathlib import Path

import streamlit as st

from triage import enrich, story, story_next_steps
from triage.checks import make_verdict, run_checks
from triage.iocs import extract_iocs
from triage.parse import read_evtx_with_status
from triage.timeline import TIME_ZONES, in_zone
from ui_common import esc, load_css
from ui_findings import show_findings
from ui_iocs import show_iocs
from ui_summary import show_summary
from ui_tree_timeline import show_domains, show_process_tree, show_timeline

TAGLINE = "sysmon log triage for SOC analysts"

st.set_page_config(page_title="SysVerdict", layout="wide", initial_sidebar_state="expanded")
SAMPLES_DIR = Path(__file__).parent / "samples"
load_css()


# ---------- loading and analysing (cached, so clicking around is instant) ----------

@st.cache_data(show_spinner=False, max_entries=5)
def analyse(file_bytes, it_installs_all):
    """Parse the log and run the checks. Cached by the file's content and the IT setting."""
    # The evtx reader reads from a file on disk: write a temporary copy, read it, delete it.
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
        tmp.write(file_bytes)
        path = tmp.name
    try:
        events, damaged = read_evtx_with_status(path)
    finally:
        os.remove(path)
    findings = run_checks(events, it_installs_all)
    return events, findings, extract_iocs(events, findings), story.build_steps(events, findings), damaged


@st.cache_data(ttl=15, show_spinner=False)
def backend_health():
    return enrich.check_health()


# ---------- sidebar ----------

with st.sidebar:
    st.markdown('<div class="wordmark">SYS<span>VERDICT</span></div>', unsafe_allow_html=True)
    st.markdown(f'<div class="muted">{TAGLINE}</div>', unsafe_allow_html=True)
    st.write("")
    uploaded = st.file_uploader("Sysmon log (.evtx)", type=["evtx"])
    # Local sample logs (the samples/ folder is git-ignored, so this only shows on your machine).
    samples = sorted(SAMPLES_DIR.glob("*.evtx")) if SAMPLES_DIR.is_dir() else []
    sample = None
    if samples and uploaded is None:
        choice = st.selectbox("...or open a local sample", ["(none)"] + [p.name for p in samples])
        sample = SAMPLES_DIR / choice if choice != "(none)" else None
    offline = st.toggle("Offline mode", value=True,
                        help="On: nothing leaves this computer. Off: hashes, public IPs and public "
                             "domains of flagged processes may be sent to the three local backends.")
    it_installs_all = st.toggle("IT installs all software", value=False,
                                help="Turn on for a client where users never install software themselves. "
                                     "Then a program installed from Downloads or another user folder counts "
                                     "as a warning sign, so admin-like actions by it (e.g. recon by a remote "
                                     "tool) are high confidence. Off: they stay low confidence.")
    zone_label = st.selectbox("Time zone", list(TIME_ZONES),
                              help="Sysmon records UTC. Pick a zone to show local time instead.")

    st.markdown("**Enrichment backends**")
    if offline:
        for name in ("Hash backend", "IP backend", "DNS backend"):
            st.markdown(f'<span class="dot off"></span>{name}: <span class="muted">offline mode</span>',
                        unsafe_allow_html=True)
    else:
        for name, is_up in backend_health().items():
            state = "up" if is_up else "down"
            st.markdown(f'<span class="dot {state}"></span>{name}: {"running" if is_up else "not running"}',
                        unsafe_allow_html=True)
    st.write("")
    st.markdown('<div class="muted">Logs stay on this computer: a temporary copy is read and deleted at '
                'once. No AI service, no telemetry, no CDN.</div>', unsafe_allow_html=True)


# ---------- empty state ----------

if uploaded is None and sample is None:
    st.markdown('<div class="wordmark wordmark-big">SYS<span>VERDICT</span></div>', unsafe_allow_html=True)
    st.markdown(f'<div class="tagline">{TAGLINE}</div>', unsafe_allow_html=True)
    left, middle, right = st.columns(3)
    left.markdown('<div class="card start"><div class="title">1. Upload</div>Sysmon logs only (.evtx). '
                  'Other Windows event logs are not supported.</div>', unsafe_allow_html=True)
    middle.markdown('<div class="card start"><div class="title">2. Analyze</div>Detects known attacker behavior.</div>',
                    unsafe_allow_html=True)
    right.markdown('<div class="card start"><div class="title">3. Respond</div>An evidence-backed verdict with clear '
                   'next steps and IOCs.</div>', unsafe_allow_html=True)
    st.stop()


# ---------- analysis ----------

if uploaded is not None:
    file_bytes, file_label = uploaded.getvalue(), uploaded.name
else:
    file_bytes, file_label = sample.read_bytes(), sample.name
file_id = hashlib.sha256(file_bytes).hexdigest()
with st.spinner("Reading the log and running the checks..."):
    try:
        events, findings, iocs, steps, damaged = analyse(file_bytes, it_installs_all)
    except Exception:  # a broken or non-evtx file must not crash the page
        st.error("This file could not be read as a Windows event log (.evtx).")
        st.stop()

if damaged:
    st.warning(f"The file is damaged; {len(events)} events were read. The verdict covers only those events.")
if not events:
    st.warning("No Sysmon events found in this file. Is it the Microsoft-Windows-Sysmon/Operational log?")
    st.stop()

events_by_id = {e["record_id"]: e for e in events}
enrichment = st.session_state.setdefault("enrichment", {}).setdefault(file_id, {})
enrichment_words = [enrich.simple_verdict(r) for r in enrichment.values() if r["status"] == "enriched"]
verdict = make_verdict(findings, enrichment_words)
moments = story.key_moments(steps)
plan = story_next_steps.next_steps(findings, verdict, steps)
attack_low, other_low = story.split_low_findings(events, findings)
zone = TIME_ZONES[zone_label]
time_note = "Times in UTC" if zone is None else f"Times in {zone_label} local time"

st.markdown(f'<div class="verdict v-{verdict["label"]}"><div class="label">{verdict["label"].upper()}</div>'
            f'<div class="reason">{esc(verdict["reason"])}</div></div>', unsafe_allow_html=True)

strong = [f for f in findings if f["strength"] == "Strong"]
columns = st.columns(5)
columns[0].metric("Events in log", f"{len(events):,}")
columns[1].metric("High-confidence findings", len(strong))
columns[2].metric("Low-confidence findings", len(findings) - len(strong))
columns[3].metric("IOCs", len(iocs))
columns[4].metric("Computers", len({e["computer"] for e in events}))
first, last = in_zone(events[0]["time"], zone), in_zone(events[-1]["time"], zone)
st.caption(f"{file_label}  |  {first:%Y-%m-%d %H:%M} to {last:%Y-%m-%d %H:%M} ({'UTC' if zone is None else zone_label})")


# ---------- the tabs (each one is drawn by a ui_*.py file) ----------

tabs = st.tabs(["Summary", "Findings", "IOCs", "Process tree", "Timeline", "Domains"])
with tabs[0]:
    show_summary(moments, plan, zone, time_note, events_by_id)
with tabs[1]:
    show_findings(findings, strong, attack_low, other_low, zone, events_by_id)
with tabs[2]:
    show_iocs(iocs, enrichment, offline, verdict)
with tabs[3]:
    show_process_tree(events, findings, steps, zone)
with tabs[4]:
    show_timeline(events, steps, zone, time_note)
with tabs[5]:
    show_domains(events, zone)
