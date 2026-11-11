"""Build the PDF report with fpdf2: verdict, key moments, next steps (NIST phases), the full story
with MITRE ATT&CK tags and IOCs with enrichment results.
The PDF is made in memory and only saved where the analyst downloads it. Times are UTC.
"""

from pathlib import Path

from fpdf import FPDF
from fpdf.fonts import FontFace

from triage.story import defang, display_name

FONTS = Path(__file__).parent.parent / "static" / "fonts"
VERDICT_COLORS = {"Malicious": (229, 72, 77), "Suspicious": (242, 169, 59), "Benign": (61, 179, 158)}
INK = (20, 26, 33)
MUTED = (100, 110, 122)
INTEL_TYPES = ("sha256", "ip", "domain")


class Report(FPDF):
    def header(self):
        self.set_font("Plex", "B", 9)
        self.set_text_color(*MUTED)
        self.cell(0, 6, "SYSVERDICT  |  incident report", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def footer(self):
        self.set_y(-12)
        self.set_font("Plex", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 6, f"Page {self.page_no()}  |  all times UTC  |  generated locally, no data left this machine",
                  align="C")


def section(pdf, title):
    pdf.ln(4)
    pdf.set_font("Plex", "B", 13)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Plex", "", 9.5)


def paragraph(pdf, text, bold=False):
    """A paragraph. URLs, domains and IPs are defanged so PDF readers don't make them clickable."""
    pdf.set_font("Plex", "B" if bold else "", 9.5)
    pdf.multi_cell(0, 5, defang(text), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Plex", "", 9.5)
    pdf.ln(1)


def table(pdf, headings, rows, widths):
    pdf.set_font("Plex", "", 8)
    heading_style = FontFace(emphasis="BOLD", fill_color=(232, 235, 239))
    with pdf.table(col_widths=widths, headings_style=heading_style, line_height=4.5,
                   first_row_as_headings=True) as t:
        header = t.row()
        for h in headings:
            header.cell(h)
        for values in rows:
            row = t.row()
            for value in values:
                row.cell(defang(str(value)))
    pdf.set_font("Plex", "", 9.5)


def reputation(ioc, enrichment):
    result = enrichment.get((ioc["type"], ioc["value"]))
    if result and result["status"] == "enriched":
        return f"{result['verdict'].replace('_', ' ')} ({result['score']}), {result['source']}"
    if result:
        return f"not checked: {result['note']}"
    return "not checked: " + ("offline mode" if ioc["enrich"] else ioc["why_not"])


def build_pdf(file_label, verdict, steps, moments, plan, findings, iocs, enrichment):
    """Return the PDF as bytes."""
    pdf = Report(orientation="P", unit="mm", format="A4")
    pdf.add_font("Plex", "", FONTS / "IBMPlexSans-Regular.ttf")
    pdf.add_font("Plex", "B", FONTS / "IBMPlexSans-Bold.ttf")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Verdict banner
    pdf.set_font("Plex", "", 9)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 5, f"Log file: {file_label}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_fill_color(*VERDICT_COLORS[verdict["label"]])
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Plex", "B", 20)
    pdf.cell(0, 14, f"  {verdict['label'].upper()}", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(*INK)
    pdf.ln(1)
    paragraph(pdf, verdict["reason"])

    section(pdf, "Key moments")
    if not moments:
        paragraph(pdf, "None of the 10 checks matched. Nothing known-bad is visible in this log; that does "
                       "not prove the computer is clean.")
    for number, s in enumerate(moments, start=1):  # numbered 1, 2, 3, ... as on the Summary tab
        paragraph(pdf, f"{s['time'][:19]}  [{s['tactic']}]  {number}. {s['text']}")

    section(pdf, "Recommended next steps (NIST SP 800-61 phases)")
    for phase, items in plan.items():
        paragraph(pdf, phase, bold=True)
        for item in items:
            paragraph(pdf, f"- {item}")

    if steps:
        pdf.add_page()
        section(pdf, "What happened, step by step")
        rows = [(s["number"], s["time"][:19], f"{s['tactic']}\n{s['technique']}",
                 s["text"] + (f" (follows step {s['follows']})" if s["follows"] else ""),
                 ", ".join(str(i) for i in s["event_ids"][:6])) for s in steps]
        table(pdf, ["#", "Time (UTC)", "MITRE ATT&CK", "What happened", "Events"], rows, (8, 24, 38, 96, 22))

    if iocs:
        section(pdf, "IOCs checked against threat intel")
        intel = [i for i in iocs if i["type"] in INTEL_TYPES]
        if intel:
            rows = [(i["type"], i["value"][:80], display_name(i["process"]), reputation(i, enrichment)[:90])
                    for i in intel]
            table(pdf, ["IOC Type", "Value", "Process", "Reputation"], rows, (16, 78, 36, 58))
        other = [i for i in iocs if i["type"] not in INTEL_TYPES]
        if other:
            section(pdf, "Other IOCs")
            rows = [(i["type"], i["value"][:110], display_name(i["process"]), i["event_id"]) for i in other]
            table(pdf, ["IOC Type", "Value", "Process", "Event #"], rows, (16, 120, 36, 16))

    return bytes(pdf.output())
