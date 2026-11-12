"""SysVerdict: the Streamlit page.

Run with:  .venv\\Scripts\\python -m streamlit run app.py

Flow: upload a .evtx -> parse -> 10 checks -> verdict -> story (steps with MITRE ATT&CK tags),
next steps (NIST phases), findings, IOCs, process tree, timeline, domains.
Enrichment is optional and off by default (offline mode).
"""

import csv
import hashlib
import html
import io
import json
import os
import tempfile
from pathlib import Path

import streamlit as st

from triage import enrich, graph, story
from triage.checks import make_verdict, run_checks
from triage.domains import classify_domains
from triage.iocs import extract_iocs
from triage.parse import read_evtx
from triage.timeline import TIME_ZONES, group_by_day, in_zone

TAGLINE = "Sysmon log triage for SOC teams"
CONFIDENCE = {"Strong": "High confidence", "Weak": "Low confidence"}
# The NIST name, shown only where it differs from the phase label.
PHASE_HELP = {"Investigate": "Detection & Analysis"}
INTEL_TYPES = ("sha256", "ip", "domain")

st.set_page_config(page_title="SysVerdict", layout="wide", initial_sidebar_state="expanded")
SAMPLES_DIR = Path(__file__).parent / "samples"

st.markdown("""
<style>
  .block-container {padding-top: 2rem; max-width: 1400px;}
  .wordmark {font-weight: 700; letter-spacing: .14em; font-size: 1rem; color: #5CC8FF;}
  .wordmark span {color: #E6E1D6;}
  .muted {color: #8B96A3; font-size: .85rem;}
  .verdict {border-radius: 8px; padding: 1.1rem 1.4rem; margin-bottom: 1rem; border-left: 8px solid;}
  .verdict .label {font-size: 2rem; font-weight: 700; letter-spacing: .08em;}
  .verdict .reason {font-size: 1rem; margin-top: .2rem;}
  .v-Malicious {background: #2A1416; border-color: #E5484D;} .v-Malicious .label {color: #E5484D;}
  .v-Suspicious {background: #2A2112; border-color: #F2A93B;} .v-Suspicious .label {color: #F2A93B;}
  .v-Benign {background: #11251F; border-color: #3DB39E;} .v-Benign .label {color: #3DB39E;}
  .chip {display: inline-block; padding: .05rem .55rem; border-radius: 99px; font-size: .72rem;
         font-weight: 600; letter-spacing: .04em; margin-right: .4rem; white-space: nowrap;}
  .chip-Strong {background: #E5484D; color: #0F1419;} .chip-Weak {background: #3A4654; color: #E6E1D6;}
  .chip-tactic {background: #2A3440; color: #5CC8FF;}
  .card {background: #1A2129; border: 1px solid #2A3440; border-radius: 6px; padding: .8rem 1rem; margin-bottom: .6rem;}
  .card .title {font-weight: 600; font-size: 1.02rem;}
  .day {font-weight: 700; color: #5CC8FF; letter-spacing: .05em; margin: .8rem 0 .3rem 0;}
  .clock {font-family: "IBM Plex Mono", monospace; color: #8B96A3; margin-right: .6rem;}
  .phase {font-weight: 700; margin-top: .6rem;} .phase span {color: #8B96A3; font-weight: 400; font-size: .8rem;}
  /* No word is ever cut with "...": the number labels at the top wrap onto a second line instead. */
  [data-testid="stMetricLabel"], [data-testid="stMetricLabel"] * {white-space: normal !important;
                overflow: visible !important; text-overflow: clip !important;}
  /* Button labels wrap too, instead of being cut. */
  button p, button div {white-space: normal !important; overflow: visible !important;
                        text-overflow: clip !important;}
  /* The small "Details" button next to each key event. */
  /* It is always as wide as the word, so "Details" is never split into letters. */
  [data-testid="stPopover"] button {min-width: max-content;}
  [data-testid="stPopover"] button p {font-size: .78rem; white-space: nowrap !important;}
  .ptree {background: #1A2129; border: 1px solid #2A3440; border-radius: 6px; padding: .7rem .9rem;
          margin-bottom: 1rem;}
  .ptree .line {display: flex; line-height: 1.75; font-size: .9rem;}
  .ptree .prefix {font-family: "IBM Plex Mono", monospace; color: #5B6B7C; white-space: pre; flex-shrink: 0;}
  .ptree .text {overflow-wrap: anywhere;}
  .ptree .label {font-weight: 600; margin-right: .5rem;}
  .ptree .malicious .label {color: #E5484D;} .ptree .attack .label {color: #5CC8FF;}
  .ptree .context .label {color: #8B96A3; font-weight: 400;}
  .ptree .action .label {font-weight: 400; font-family: "IBM Plex Mono", monospace; font-size: .8rem;}
  .ptree .detail {font-family: "IBM Plex Mono", monospace; font-size: .78rem; color: #8B96A3; margin-right: .5rem;}
  .ptree .meta {font-size: .75rem; color: #8B96A3; margin-right: .5rem;}
  .htable {max-height: 640px; overflow-y: auto; border: 1px solid #2A3440; border-radius: 6px; margin-bottom: 1rem;}
  .htable table {width: 100%; border-collapse: collapse; font-size: .9rem;}
  .htable th {position: sticky; top: 0; background: #1A2129; text-align: left; padding: .5rem .7rem;
              color: #8B96A3; font-weight: 600; border-bottom: 1px solid #2A3440; white-space: nowrap;}
  .htable td {padding: .45rem .7rem; border-bottom: 1px solid #1E262F; vertical-align: top;
              white-space: normal; overflow-wrap: anywhere;}
  .htable td.short {white-space: nowrap; font-family: "IBM Plex Mono", monospace; font-size: .8rem; color: #8B96A3;}
  .dot {display: inline-block; width: .6rem; height: .6rem; border-radius: 50%; margin-right: .45rem;}
  .up {background: #3DB39E;} .down {background: #E5484D;} .off {background: #5B6B7C;}
</style>
""", unsafe_allow_html=True)


def esc(text):
    """Log text shown on the page: escape it so a crafted log cannot inject HTML, and show
    URLs, domains and IPs as code text, which is never a clickable link."""
    return story.code_addresses(html.escape(str(text), quote=False))


def html_table(rows, short_columns=()):
    """Draw a list of row dicts as a plain HTML table whose long values wrap, so nothing is cut
    (st.dataframe cuts long hashes and paths). Columns named in short_columns stay on one line.
    Raw HTML is never turned into links, so addresses are shown as-is but cannot be clicked."""
    if not rows:
        return
    header = "".join(f"<th>{html.escape(name)}</th>" for name in rows[0])
    body = ""
    for row in rows:
        cells = ""
        for name, value in row.items():
            css = ' class="short"' if name in short_columns else ""
            cells += f"<td{css}>{html.escape(str(value))}</td>"
        body += f"<tr>{cells}</tr>"
    st.markdown(f'<div class="htable"><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table></div>',
                unsafe_allow_html=True)


# ---------- loading and analysing (cached, so clicking around is instant) ----------

@st.cache_data(show_spinner=False, max_entries=5)
def analyse(file_bytes):
    """Parse the log and run the checks. Cached by the file's content."""
    # python-evtx reads from a file on disk: write a temporary copy, read it, delete it.
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
        tmp.write(file_bytes)
        path = tmp.name
    try:
        events = read_evtx(path)
    finally:
        os.remove(path)
    findings = run_checks(events)
    return events, findings, extract_iocs(events, findings), story.build_steps(events, findings)


@st.cache_data(ttl=15, show_spinner=False)
def backend_health():
    return enrich.check_health()


def show_raw_events(event_ids, limit=5):
    """Show the raw events behind a claim, so the analyst can check it."""
    for event_id in event_ids[:limit]:
        st.caption(f"Event #{event_id}")
        st.json(events_by_id[event_id], expanded=False)
    if len(event_ids) > limit:
        st.caption(f"... and {len(event_ids) - limit} more: see All events on the Timeline tab.")


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
    st.markdown('<div class="muted">Logs are read in memory on this computer. No AI service, no '
                'telemetry, no CDN.</div>', unsafe_allow_html=True)


# ---------- empty state ----------

if uploaded is None and sample is None:
    st.markdown('<div class="wordmark" style="font-size:1.8rem">SYS<span>VERDICT</span></div>',
                unsafe_allow_html=True)
    st.markdown(f"### {TAGLINE}")
    left, middle, right = st.columns(3)
    left.markdown('<div class="card"><div class="title">1. Upload</div>Export the Sysmon log '
                  '(Event Viewer, or <code>wevtutil epl Microsoft-Windows-Sysmon/Operational '
                  'host.evtx</code>) and drop it in the sidebar.</div>', unsafe_allow_html=True)
    middle.markdown('<div class="card"><div class="title">2. Triage</div>10 checks look for known '
                    'attack behaviour. Every finding points to the exact events behind it.</div>',
                    unsafe_allow_html=True)
    right.markdown('<div class="card"><div class="title">3. Act</div>Get a verdict, the attack story '
                   'with MITRE ATT&amp;CK tags, next steps and IOCs for the ticket.</div>',
                   unsafe_allow_html=True)
    st.stop()


# ---------- analysis ----------

if uploaded is not None:
    file_bytes, file_label = uploaded.getvalue(), uploaded.name
else:
    file_bytes, file_label = sample.read_bytes(), sample.name
file_id = hashlib.sha256(file_bytes).hexdigest()
with st.spinner("Reading the log and running the checks..."):
    try:
        events, findings, iocs, steps = analyse(file_bytes)
    except Exception:  # a broken or non-evtx file must not crash the page
        st.error("This file could not be read as a Windows event log (.evtx).")
        st.stop()

if not events:
    st.warning("No Sysmon events found in this file. Is it the Microsoft-Windows-Sysmon/Operational log?")
    st.stop()

events_by_id = {e["record_id"]: e for e in events}
enrichment = st.session_state.setdefault("enrichment", {}).setdefault(file_id, {})
enrichment_words = [enrich.simple_verdict(r) for r in enrichment.values() if r["status"] == "enriched"]
verdict = make_verdict(findings, enrichment_words)
moments = story.key_moments(steps)
plan = story.next_steps(findings, verdict, steps)
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

tabs = st.tabs(["Summary", "Findings", "IOCs", "Process tree", "Timeline", "Domains"])


def step_row(clock, step, number):
    """One key event: time, ATT&CK tactic (technique on hover), number, sentence, Details button."""
    text_column, details_column = st.columns([5, 1])
    low = '<span class="chip chip-Weak">LOW CONFIDENCE</span>' if step["confidence"] == "Low" else ""
    body = (f'<span class="clock">{clock}</span>'
            f'<span class="chip chip-tactic" title="{html.escape(step["technique"])}">{esc(step["tactic"])}</span>{low}'
            f'<b>{number}.</b> {esc(step["text"])}')
    text_column.markdown(body, unsafe_allow_html=True)
    with details_column.popover("Details", key=f"moment-{number}", width="stretch"):
        show_raw_events(step["event_ids"])


# ---------- Summary ----------

with tabs[0]:
    left, right = st.columns([3, 2], gap="large")
    with left:
        st.subheader("Events")
        if not moments:
            st.markdown("None of the 10 checks matched. Nothing known-bad is visible in this log; "
                        "that does not prove the computer is clean.")
        else:
            st.caption(f"Key events of the incident. {time_note}. Details shows the Event # "
                       "to find each one on the Timeline.")
            number = 0  # the key events are numbered 1, 2, 3, ... in the order shown
            for day, rows in group_by_day(moments, zone):
                st.markdown(f'<div class="day">{day}</div>', unsafe_allow_html=True)
                for clock, step in rows:
                    number += 1
                    step_row(clock, step, number)
    with right:
        st.subheader("Next steps")
        st.caption("Grouped by NIST SP 800-61 incident-response phase.")
        for phase, items in plan.items():
            note = f" <span>({PHASE_HELP[phase]})</span>" if phase in PHASE_HELP else ""
            st.markdown(f'<div class="phase">{phase}{note}</div>', unsafe_allow_html=True)
            st.markdown("\n".join(f"- {esc(item)}" for item in items))


# ---------- Findings ----------

def finding_card(f, key):
    st.markdown(f'<div class="card"><span class="chip chip-{f["strength"]}">{CONFIDENCE[f["strength"]].upper()}</span>'
                f'<span class="title">{esc(f["title"])}</span><br>'
                f'<span class="muted">{in_zone(f["time"], zone):%Y-%m-%d %H:%M:%S} | '
                f'{esc(story.display_name(f["process"]))}</span><br>{esc(f["detail"])}</div>',
                unsafe_allow_html=True)
    with st.expander(f"Raw events ({len(f['event_ids'])})", key=key):
        show_raw_events(f["event_ids"])


with tabs[1]:
    if not findings:
        st.success("None of the 10 checks matched. Nothing known-bad is visible in this log.")
    attack = sorted(strong + attack_low, key=lambda f: f["time"]) if strong else []
    if attack:
        st.subheader("Part of the attack")
        st.caption("High-confidence findings, and low-confidence ones from the same malicious programs.")
        for number, f in enumerate(attack):
            finding_card(f, f"attack-{number}")
    if other_low:
        with st.expander(f"Other activity worth a look ({len(other_low)}): low confidence, "
                         "often normal installers", expanded=not strong):
            for number, f in enumerate(other_low):
                finding_card(f, f"other-{number}")


# ---------- IOCs ----------

def reputation(ioc):
    """('Suspicious (50)', 'hash backend', note) or ('not checked: reason', '', '')."""
    result = enrichment.get((ioc["type"], ioc["value"]))
    if result and result["status"] == "enriched":
        return f"{result['verdict'].replace('_', ' ').capitalize()} ({result['score']})", result["source"], result["note"]
    if result:
        return f"not checked: {result['note']}", result["source"], ""
    if not ioc["enrich"]:
        return f"not checked: {ioc['why_not']}", "", ""
    return "not checked: " + ("offline mode" if offline else "press Enrich IOCs"), "", ""


with tabs[2]:
    if not iocs:
        st.info("No IOCs: no process was flagged.")
    else:
        intel = [i for i in iocs if i["type"] in INTEL_TYPES]
        other = [i for i in iocs if i["type"] not in INTEL_TYPES]

        st.subheader("Checked against threat intel")
        st.caption("Hashes, public IPv4 addresses and public domains of the flagged programs. Only these "
                   "can be sent to the enrichment backends; everything else stays on this computer.")
        if offline:
            st.info("Offline mode is on: nothing is sent. Turn it off in the sidebar to enrich.")
        elif verdict["label"] == "Benign":
            st.info("Enrichment runs only when the verdict is Suspicious or Malicious.")
        elif intel:
            waiting = any("press Enrich more" in r["note"] for r in enrichment.values())
            if st.button("Enrich more" if waiting else "Enrich IOCs", type="primary"):
                progress = st.progress(0.0, text="Asking the backends...")

                def on_progress(number, total, ioc):
                    progress.progress(number / total, text=f"{number}/{total}: {ioc['type']} {ioc['value'][:60]}")

                enrichment.update(enrich.enrich_all(iocs, on_progress))
                progress.empty()
                st.rerun()
        if intel:
            html_table([{"IOC Type": i["type"], "Value": i["value"], "Process": story.display_name(i["process"]),
                         "Reputation": reputation(i)[0], "Checked by": reputation(i)[1]} for i in intel],
                       short_columns=("IOC Type",))
            notes = [(i["value"], reputation(i)[2]) for i in intel if reputation(i)[2]]
            if notes:
                with st.expander("What each source said"):
                    for value, note in notes:
                        st.markdown(f"**{esc(value)}**: {esc(note)}")

        if other:
            st.subheader("Other IOCs")
            st.caption("For hunting on other computers and in other tools; not sent anywhere.")
            html_table([{"IOC Type": i["type"], "Value": i["value"], "Process": story.display_name(i["process"]),
                         "Event #": i["event_id"]} for i in other], short_columns=("IOC Type", "Event #"))

        rows = [{"IOC Type": i["type"], "Value": i["value"], "Process": story.display_name(i["process"]),
                 "Reputation": reputation(i)[0], "Note": reputation(i)[2], "Event #": i["event_id"]} for i in iocs]
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
        left, right = st.columns([1, 3])
        left.download_button("Download all IOCs (CSV)", buffer.getvalue(), "iocs.csv", "text/csv")
        with right.expander("Copy values (one per line)"):
            st.code("\n".join(i["value"] for i in iocs), language=None)


# ---------- Process tree ----------

def h(text):
    """Escape text for the tree below (raw HTML blocks never turn addresses into links)."""
    return html.escape(str(text))


with tabs[3]:
    tree_rows = graph.build_process_tree(events, findings, steps)
    if not tree_rows:
        st.info("No attack steps, so there is no process tree to show.")
    else:
        lines = []
        for row in tree_rows:
            detail = f'<span class="detail">{h(row["detail"])}</span>' if row["detail"] else ""
            meta = f'<span class="meta">{h(row["meta"])}</span>' if row["meta"] else ""
            tactic = f'<span class="chip chip-tactic">{h(row["step"])}</span>' if row["step"] else ""
            # Each level deeper is indented 1.6rem more and starts with "└─"; the text wraps under itself.
            indent = max(row["depth"] - 1, 0) * 1.6
            marker = "└─ " if row["depth"] > 0 else ""
            lines.append(f'<div class="line {row["kind"]}" style="margin-left: {indent}rem">'
                         f'<span class="prefix">{marker}</span>'
                         f'<span class="text"><span class="label">{h(row["label"])}</span>'
                         f'{detail}{meta}{tactic}</span></div>')
        st.markdown(f'<div class="ptree">{"".join(lines)}</div>', unsafe_allow_html=True)


# ---------- Timeline ----------

with tabs[4]:
    show_all = st.toggle("Show all events, not only the story", value=not steps)
    rows = story.story_rows(events, steps, zone, include_all=show_all)
    st.caption(f"{len(rows):,} events. {time_note}. The Sysmon Event ID can be searched as-is in any SIEM.")
    if rows:
        html_table(rows, short_columns=(list(rows[0])[0], "Sysmon Event ID", "Event #"))

    shown_ids = {r["Event #"] for r in rows}
    buffer = io.StringIO()
    if rows:
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    left, right, _ = st.columns([1, 2, 1])
    left.download_button("Download CSV", buffer.getvalue(), "timeline.csv", "text/csv")
    right.download_button("Download JSON (every Sysmon field)",
                          json.dumps([e for e in events if e["record_id"] in shown_ids], indent=1),
                          "events.json", "application/json")


# ---------- Domains ----------

with tabs[5]:
    domain_rows = classify_domains(events)
    st.caption("Sysmon does not record which page asked for a domain, so these labels are guesses: the "
               "first browser lookup after a quiet moment is likely a site the user visited; lookups right "
               "after it are likely that page's resources; ad/CDN/telemetry names come from a local list "
               "(data/ad_cdn_domains.txt).")
    labels = sorted({r["label"] for r in domain_rows})
    chosen = st.multiselect("Show", labels, default=[l for l in labels if l != "internal name"])
    shown = [r for r in domain_rows if r["label"] in chosen]
    time_column = "Time (UTC)" if zone is None else "Local time"
    html_table([{time_column: f"{in_zone(r['time'], zone):%Y-%m-%d %H:%M:%S}", "Domain": r["domain"],
                 "Label": r["label"], "Program": r["program"], "Event #": r["event_id"]} for r in shown],
               short_columns=(time_column, "Event #"))
