"""The Process tree, Timeline and Domains tabs."""

import csv
import io
import json

import streamlit as st

from triage import graph, story_timeline
from triage.domains import classify_domains
from triage.timeline import in_zone
from ui_common import h, html_table


def show_process_tree(events, findings, steps, zone):
    tree_rows = graph.build_process_tree(events, findings, steps, zone)
    if not tree_rows:
        st.info("No attack steps, so there is no process tree to show.")
        return
    # Each 4-character piece of the prefix ("│   ", "├── ", "└── ", "    ") becomes one CSS shape.
    SEGMENT_CLASS = {"│   ": "bar", "├── ": "tee", "└── ": "end", "    ": "blank"}
    lines = []
    for row in tree_rows:
        pieces = [row["prefix"][i:i + 4] for i in range(0, len(row["prefix"]), 4)]
        tree_lines = "".join(f'<span class="seg {SEGMENT_CLASS[piece]}"></span>' for piece in pieces)
        detail = f'<span class="detail">{h(row["detail"])}</span>' if row["detail"] else ""
        tactic = f'<span class="chip chip-tactic">{h(row["step"])}</span>' if row["step"] else ""
        # Column 1: the tree lines and the name, which wraps under itself.
        # Column 2: the time. Column 3: the details, then the blue tactic chip.
        lines.append(f'<div class="line {row["kind"]}">'
                     f'<span class="tree">{tree_lines}'
                     f'<span class="text"><span class="label">{h(row["label"])}</span></span></span>'
                     f'<span class="time">{h(row["time"])}</span>'
                     f'<span class="info">{detail}{tactic}</span></div>')
    st.markdown(f'<div class="ptree">{"".join(lines)}</div>', unsafe_allow_html=True)


def stack_timeline_row(row):
    """A copy of one Timeline row for the page, with short values on two lines so the Event
    column gets the room:
      '2023-12-13 10:53:32'                               -> '2023-12-13' / '10:53:32'
      '1 – Process Create'                                -> '1' / 'Process Create'
      'Execution · T1204.002 User Execution: Malicious File' -> 'T1204.002' / 'Execution · User Execution: ...'
    The CSV export keeps the original one-line values."""
    time_name = list(row)[0]  # "Time (UTC)" or "Local time"
    event_number, event_name = row["Sysmon Event ID"].split(" – ", 1)
    tag = row["MITRE ATT&CK"]
    if " · " in tag:  # tactic and technique: put the technique code on top
        tactic, technique = tag.split(" · ", 1)
        code, technique_name = technique.split(" ", 1)
        tag = f"{code}\n{tactic} · {technique_name}"
    return {time_name: row[time_name].replace(" ", "\n"),
            "Sysmon Event ID": f"{event_number}\n{event_name}",
            "MITRE ATT&CK": tag,
            "Event": row["Event"],
            "Event #": row["Event #"]}


def show_timeline(events, steps, zone, time_note):
    # Only the events that lead to the incident (the events behind the attack story).
    rows = story_timeline.story_rows(events, steps, zone)
    if not rows:
        st.info("No incident events to show.")
        return
    st.caption(f"{len(rows):,} incident events. {time_note}. "
               "The Sysmon Event ID can be searched as-is in any SIEM.")
    html_table([stack_timeline_row(r) for r in rows],
               short_columns=(list(rows[0])[0], "Event #"),
               narrow_columns=("Sysmon Event ID", "MITRE ATT&CK"))

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    shown_ids = {r["Event #"] for r in rows}
    left, right, _ = st.columns([1, 2, 1])
    left.download_button("Download CSV", buffer.getvalue(), "timeline.csv", "text/csv")
    right.download_button("Download JSON (every Sysmon field)",
                          json.dumps([e for e in events if e["record_id"] in shown_ids], indent=1),
                          "events.json", "application/json")


def show_domains(events, zone):
    domain_rows = classify_domains(events)
    st.caption("Sysmon does not record which page asked for a domain, so these labels are guesses: the "
               "first browser lookup after a quiet moment is likely a site the user visited; lookups right "
               "after it are likely that page's resources; ad/CDN/telemetry names come from a local list "
               "(data/ad_cdn_domains.txt).")
    labels = sorted({r["label"] for r in domain_rows})
    chosen = st.multiselect("Show", labels, default=[l for l in labels if l != "internal name"])
    shown = [r for r in domain_rows if r["label"] in chosen]
    time_column = "Time (UTC)" if zone is None else "Local time"
    # Date above time ("\n"), like the Timeline, so the Domain column gets the room.
    html_table([{time_column: f"{in_zone(r['time'], zone):%Y-%m-%d\n%H:%M:%S}", "Domain": r["domain"],
                 "Label": r["label"], "Program": r["program"], "Event #": r["event_id"]} for r in shown],
               short_columns=(time_column, "Event #"))
