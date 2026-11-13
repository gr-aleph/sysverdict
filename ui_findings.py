"""The Findings tab: one card per finding, the attack's findings first, other low ones folded away."""

import streamlit as st

from triage import display
from triage.timeline import in_zone
from ui_common import esc, show_raw_events

CONFIDENCE = {"Strong": "High confidence", "Weak": "Low confidence"}


def finding_card(f, key, zone, events_by_id):
    st.markdown(f'<div class="card"><span class="chip chip-{f["strength"]}">{CONFIDENCE[f["strength"]].upper()}</span>'
                f'<span class="title">{esc(f["title"])}</span><br>'
                f'<span class="muted">{in_zone(f["time"], zone):%Y-%m-%d %H:%M:%S} | '
                f'{esc(display.display_name(f["process"]))}</span><br>{esc(f["detail"])}</div>',
                unsafe_allow_html=True)
    with st.expander(f"Raw events ({len(f['event_ids'])})", key=key):
        show_raw_events(f["event_ids"], events_by_id)


def show_findings(findings, strong, attack_low, other_low, zone, events_by_id):
    if not findings:
        st.success("None of the checks matched. Nothing known-bad is visible in this log.")
    attack = sorted(strong + attack_low, key=lambda f: f["time"]) if strong else []
    if attack:
        st.caption("High- and low-confidence findings and related activity.")
        for number, f in enumerate(attack):
            finding_card(f, f"attack-{number}", zone, events_by_id)
    if other_low:
        with st.expander(f"Other activity worth a look ({len(other_low)}): low confidence, "
                         "often normal installers", expanded=not strong):
            for number, f in enumerate(other_low):
                finding_card(f, f"other-{number}", zone, events_by_id)
