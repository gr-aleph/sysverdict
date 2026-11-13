"""Page helpers shared by the tabs: the CSS, plain HTML tables and the raw-event viewer."""

import html
from pathlib import Path

import streamlit as st

from triage import display

esc = display.esc  # log text made safe for the page (see display.esc)
CSS_FILE = Path(__file__).parent / "static" / "style.css"


def load_css():
    """Add the page's styles (static/style.css) to the page."""
    st.markdown(f"<style>\n{CSS_FILE.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


def h(text):
    """Escape text for raw HTML blocks such as the process tree (they never turn addresses into links)."""
    return html.escape(str(text))


def html_table(rows, short_columns=(), narrow_columns=()):
    """Draw a list of row dicts as a plain HTML table whose long values wrap, so nothing is cut
    (st.dataframe cuts long hashes and paths). Columns named in short_columns stay on one line;
    columns in narrow_columns get a fixed narrow width and wrap. A "\\n" in a value starts a new
    line in the cell. Raw HTML is never turned into links, so addresses cannot be clicked."""
    if not rows:
        return
    header = "".join(f"<th>{html.escape(name)}</th>" for name in rows[0])
    body = ""
    for row in rows:
        cells = ""
        for name, value in row.items():
            css = ""
            if name in short_columns:
                css = ' class="short"'
            elif name in narrow_columns:
                css = ' class="narrow"'
            # Escape first (so log text cannot inject HTML), then turn line breaks into <br>.
            cells += f"<td{css}>{html.escape(str(value)).replace(chr(10), '<br>')}</td>"
        body += f"<tr>{cells}</tr>"
    st.markdown(f'<div class="htable"><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table></div>',
                unsafe_allow_html=True)


def show_raw_events(event_ids, events_by_id, limit=5):
    """Show the raw events behind a claim, so the analyst can check it."""
    for event_id in event_ids[:limit]:
        st.caption(f"Event #{event_id}")
        st.json(events_by_id[event_id], expanded=False)
    if len(event_ids) > limit:
        st.caption(f"... and {len(event_ids) - limit} more: see the Timeline tab.")
