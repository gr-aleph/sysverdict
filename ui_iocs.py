"""The IOCs tab: enrichable IOCs (with the Enrich button), other IOCs, and the CSV / copy exports."""

import streamlit as st

from triage import display, enrich
from ui_common import csv_bytes, esc, html_table

INTEL_TYPES = ("sha256", "ip", "domain")


def reputation(ioc, enrichment, offline):
    """('Suspicious (50)', 'hash backend', note) or ('not checked: reason', '', '')."""
    result = enrichment.get((ioc["type"], ioc["value"]))
    if result and result["status"] == "enriched":
        return f"{result['verdict'].replace('_', ' ').capitalize()} ({result['score']})", result["source"], result["note"]
    if result:
        return f"not checked: {result['note']}", result["source"], ""
    if not ioc["enrich"]:
        return f"not checked: {ioc['why_not']}", "", ""
    return "not checked: " + ("offline mode" if offline else "press Enrich IOCs"), "", ""


def show_iocs(iocs, enrichment, offline, verdict):
    if not iocs:
        st.info("No IOCs: no process was flagged.")
        return
    intel = [i for i in iocs if i["type"] in INTEL_TYPES]
    other = [i for i in iocs if i["type"] not in INTEL_TYPES]

    st.subheader("Enrichable IOCs")
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
                # Called each time a lookup is answered (up to 4 run at the same time).
                progress.progress(number / total, text=f"{number}/{total} answered: {ioc['type']} {ioc['value'][:60]}")

            enrichment.update(enrich.enrich_all(iocs, on_progress))
            progress.empty()
            st.rerun()
    if intel:
        html_table([{"IOC Type": i["type"], "Value": i["value"], "Process": display.display_name(i["process"]),
                     "Reputation": reputation(i, enrichment, offline)[0],
                     "Checked by": reputation(i, enrichment, offline)[1]} for i in intel],
                   short_columns=("IOC Type",))
        notes = [(i["value"], reputation(i, enrichment, offline)[2]) for i in intel
                 if reputation(i, enrichment, offline)[2]]
        if notes:
            with st.expander("What each source said"):
                for value, note in notes:
                    st.markdown(f"**{esc(value)}**: {esc(note)}", unsafe_allow_html=True)

    if other:
        st.subheader("Other IOCs")
        st.caption("For hunting on other computers and in other tools; not sent anywhere.")
        html_table([{"IOC Type": i["type"], "Value": i["value"], "Process": display.display_name(i["process"]),
                     "Event #": i["event_id"]} for i in other], short_columns=("IOC Type", "Event #"))

    rows = [{"IOC Type": i["type"], "Value": i["value"], "Process": display.display_name(i["process"]),
             "Reputation": reputation(i, enrichment, offline)[0], "Note": reputation(i, enrichment, offline)[2],
             "Event #": i["event_id"]} for i in iocs]
    left, right = st.columns([1, 3])
    left.download_button("Download all IOCs (CSV)", csv_bytes(rows), "iocs.csv", "text/csv")
    with right.expander("Copy values (one per line)"):
        st.code("\n".join(i["value"] for i in iocs), language=None)
