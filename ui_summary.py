"""The Summary tab: the numbered key events of the incident and the next steps by NIST phase."""

import html

import streamlit as st

from triage.timeline import group_by_day
from ui_common import esc, show_raw_events

# The NIST name, shown only where it differs from the phase label.
PHASE_HELP = {"Investigate": "Detection & Analysis"}


def step_row(clock, step, number, events_by_id):
    """One key event: number, time, ATT&CK tactic (technique on hover), sentence, Details button."""
    text_column, details_column = st.columns([5, 1])
    low = '<span class="chip chip-Weak">LOW CONFIDENCE</span>' if step["confidence"] == "Low" else ""
    body = (f'<b>{number}.</b> <span class="clock">{clock}</span>'
            f'<span class="chip chip-tactic" title="{html.escape(step["technique"])}">{esc(step["tactic"])}</span>{low}'
            f'{esc(step["text"])}')
    text_column.markdown(body, unsafe_allow_html=True)
    with details_column.popover("Details", key=f"moment-{number}", width="stretch"):
        show_raw_events(step["event_ids"], events_by_id)


def show_summary(moments, plan, zone, time_note, events_by_id):
    """Key events on the left, next steps on the right."""
    left, right = st.columns([3, 2], gap="large")
    with left:
        st.subheader("Events")
        if not moments:
            st.markdown("None of the checks matched. Nothing known-bad is visible in this log; "
                        "that does not prove the computer is clean.")
        else:
            st.caption(f"Key events of the incident. {time_note}. Details shows the Event # "
                       "to find each one on the Timeline.")
            number = 0  # the key events are numbered 1, 2, 3, ... in the order shown
            for day, rows in group_by_day(moments, zone):
                st.markdown(f'<div class="day">{day}</div>', unsafe_allow_html=True)
                for clock, step in rows:
                    number += 1
                    step_row(clock, step, number, events_by_id)
    with right:
        st.subheader("Next steps")
        st.caption("Grouped by NIST SP 800-61 incident-response phase.")
        for phase, items in plan.items():
            note = f" <span>({PHASE_HELP[phase]})</span>" if phase in PHASE_HELP else ""
            st.markdown(f'<div class="phase">{phase}{note}</div>', unsafe_allow_html=True)
            # unsafe_allow_html lets the <code> tags from esc() through; esc() already escaped the text.
            st.markdown("\n".join(f"- {esc(item)}" for item in items), unsafe_allow_html=True)
