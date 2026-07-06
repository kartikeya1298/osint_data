"""
generate_summary_report.py
Builds a PDF summary report of military_osint_master.csv  -  total findings,
category/severity/source breakdowns, country coverage, and a few notable
highlighted findings. Run: python generate_summary_report.py
"""
import csv
from collections import Counter
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)

MASTER_CSV = "military_osint_master.csv"
OUTPUT_PDF = "Military_OSINT_Summary_Report.pdf"

CATEGORY_NAMES = {
    "T1": "Personnel & Identity Threats",
    "T2": "Data & Document Leakage",
    "T3": "Communication & Network Attacks",
    "T4": "Navigation, Positioning & Electronic Warfare",
    "T5": "Critical Infrastructure Attacks",
    "T6": "Malware & Advanced Cyber Attacks",
    "T7": "Emerging & Autonomous System Threats",
    "T8": "Information Operations & Influence Threats",
}

COUNTRY_KEYS = [
    "United States", "US", "India", "China", "Pakistan", "United Kingdom", "UK",
    "Germany", "Canada", "Australia", "Israel", "France", "Japan", "South Korea",
    "Taiwan", "Ukraine", "NATO",
]


def load_rows():
    with open(MASTER_CSV, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def build_report():
    rows = load_rows()
    total = len(rows)

    by_cat = Counter(r.get("category_code") for r in rows)
    by_sev = Counter(r.get("severity") for r in rows)
    by_conf = Counter(r.get("confidence") for r in rows)
    by_layer = Counter(r.get("source_layer") for r in rows)
    by_source = Counter(r.get("source") for r in rows)
    by_loc = Counter(r.get("location") for r in rows)
    distinct_sources = len(by_source)

    country_total = sum(by_loc.get(k, 0) for k in COUNTRY_KEYS)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=22, spaceAfter=6)
    subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=11,
                                     textColor=colors.HexColor("#555555"), spaceAfter=18)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=18, spaceAfter=8,
                         textColor=colors.HexColor("#1a1a2e"))
    body = ParagraphStyle("BodyCustom", parent=styles["Normal"], fontSize=10, leading=14)
    small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=8.5,
                            textColor=colors.HexColor("#777777"))

    story = []

    # ── Title ──
    story.append(Paragraph("Military Cyber Threat OSINT", title_style))
    story.append(Paragraph("Intelligence Summary Report", subtitle_style))
    story.append(Paragraph(
        f"Generated {datetime.now().strftime('%B %d, %Y')} &nbsp;|&nbsp; "
        f"Data source: <b>military_osint_master.csv</b>", small))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc"), spaceBefore=8, spaceAfter=16))

    # ── Executive summary ──
    story.append(Paragraph("Executive Summary", h2))
    summary_data = [
        ["Total unique threat entries", f"{total:,}"],
        ["Distinct data sources", f"{distinct_sources}"],
        ["Threat categories (T1-T8)", "8"],
        ["Countries / regions with dedicated coverage", "13+ (US, UK, Germany, Canada, Australia, India, Pakistan, China, Israel, France, Japan, South Korea, Taiwan, Ukraine, NATO)"],
        ["CRITICAL-severity findings", f"{by_sev.get('CRITICAL', 0):,}"],
        ["HIGH-confidence findings", f"{by_conf.get('HIGH', 0):,}  ({by_conf.get('HIGH',0)*100//total}% of total)"],
    ]
    t = Table(summary_data, colWidths=[3.0*inch, 3.4*inch])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#eeeeee")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#222222")),
    ]))
    story.append(t)

    story.append(Paragraph(
        "The dataset aggregates threat intelligence collected from ~40 free and paid OSINT "
        "sources  -  certificate transparency logs, exposed cloud storage buckets, dark web "
        "search, ransomware leak-site monitoring, satellite tracking, CVE/vulnerability feeds, "
        "Telegram OSINT channels, and defence news  -  filtered through a shared relevance engine "
        "so that only military-, government-, and defence-contractor-relevant findings are retained.",
        body))

    # ── Category breakdown ──
    story.append(Paragraph("Breakdown by Threat Category", h2))
    cat_rows = [["Code", "Category", "Count", "% of Total"]]
    for code, name in CATEGORY_NAMES.items():
        cnt = by_cat.get(code, 0)
        pct = f"{cnt*100/total:.1f}%"
        cat_rows.append([code, name, f"{cnt:,}", pct])
    cat_table = Table(cat_rows, colWidths=[0.5*inch, 3.6*inch, 0.8*inch, 0.9*inch])
    cat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f4f8")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (2, 0), (3, -1), "CENTER"),
    ]))
    story.append(cat_table)

    # ── Severity / confidence / layer breakdown ──
    story.append(Paragraph("Severity, Confidence & Source-Layer Distribution", h2))
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_rows = [["Severity", "Count", "%"]] + [
        [s, f"{by_sev.get(s,0):,}", f"{by_sev.get(s,0)*100/total:.1f}%"] for s in sev_order
    ]
    conf_rows = [["Confidence", "Count", "%"]] + [
        [c, f"{by_conf.get(c,0):,}", f"{by_conf.get(c,0)*100/total:.1f}%"] for c in ["HIGH", "MEDIUM", "LOW"]
    ]
    layer_rows = [["Layer", "Count", "%"]] + [
        [l, f"{by_layer.get(l,0):,}", f"{by_layer.get(l,0)*100/total:.1f}%"]
        for l in ["Surface Web", "Deep Web", "Dark Web"]
    ]

    def side_table(data):
        tt = Table(data, colWidths=[1.3*inch, 0.7*inch, 0.6*inch])
        tt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3a3a5e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f4f8")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ALIGN", (1, 0), (2, -1), "CENTER"),
        ]))
        return tt

    triple = Table(
        [[side_table(sev_rows), side_table(conf_rows), side_table(layer_rows)]],
        colWidths=[2.7*inch, 2.7*inch, 2.7*inch]
    )
    triple.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(triple)

    # ── Top sources ──
    story.append(Paragraph("Top Data Sources", h2))
    src_rows = [["Source", "Findings"]]
    for src, cnt in by_source.most_common(15):
        src_rows.append([src, f"{cnt:,}"])
    src_table = Table(src_rows, colWidths=[4.8*inch, 1.0*inch])
    src_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f4f8")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]))
    story.append(src_table)

    story.append(PageBreak())

    # ── Free vs paid tools ──
    story.append(Paragraph("Free vs. Paid Tools", h2))
    story.append(Paragraph(
        f"All {total:,} findings in this dataset were produced entirely by <b>free-tier sources</b> "
        f"({distinct_sources} of them, active and contributing data). The tool also has paid/premium "
        f"integrations built in, but none are currently active on this account -- either not "
        f"configured, or blocked by free-tier account limits (noted below).", body))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Free sources actively contributing data:", ParagraphStyle(
        "FreeHead", parent=body, fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=4)))
    cell_style = ParagraphStyle("Cell", parent=body, fontSize=9, leading=11.5)
    cell_style_bold = ParagraphStyle("CellBold", parent=cell_style, fontName="Helvetica-Bold")
    header_style = ParagraphStyle("HeaderCell", parent=cell_style_bold, textColor=colors.white)

    def P(text, bold=False, header=False):
        style = header_style if header else (cell_style_bold if bold else cell_style)
        return Paragraph(text, style)

    free_groups = [
        ("Certificate transparency", "crt.sh"),
        ("Internet-wide scanners", "URLScan.io, LeakIX, GrayHatWarfare"),
        ("Malware / threat-intel feeds", "ThreatFox, MalwareBazaar, OTX AlienVault, URLhaus, Feodo Tracker, VirusTotal (free tier)"),
        ("Vulnerability feeds", "CISA KEV, NVD, CIRCL CVE API"),
        ("Satellite / navigation tracking", "Celestrak SATCAT, OpenSky Network"),
        ("Code repositories", "GitHub code search"),
        ("Dark web", "Torch (.onion search via Tor)"),
        ("Ransomware leak-site tracking", "ransomware.live"),
        ("Defence news / RSS", "Defense News, BBC World/Defence, The War Zone, Breaking Defense, C4ISRNET, "
                                "Army/Navy/Air Force Times, CyberScoop, BleepingComputer, The Hacker News, "
                                "Livefist Defence, Asia-Pacific Defence Reporter, Zone Militaire/Opex360"),
        ("Social media monitoring", "Telegram (public channels)"),
    ]
    free_rows = [[P("Category", header=True), P("Sources", header=True)]] + [[P(c, True), P(s)] for c, s in free_groups]
    free_table = Table(free_rows, colWidths=[1.9*inch, 4.9*inch])
    free_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f6f43")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f7f2")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(free_table)

    story.append(Spacer(1, 14))
    story.append(Paragraph("Paid / premium tools built into the tool (not currently active):", ParagraphStyle(
        "PaidHead", parent=body, fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=4)))
    paid_data = [
        ["Shodan", "$69/mo", "Configured, but account has 0 query credits"],
        ["Censys", "Free tier available (250/mo)", "Configured, but returning authorization errors"],
        ["SecurityTrails", "$50/mo", "Not configured"],
        ["IntelligenceX", "~$100/mo", "Not configured"],
        ["DeHashed", "$15/mo", "Not configured"],
        ["BinaryEdge", "$50/mo", "Not configured"],
        ["Recorded Future", "~$25,000+/yr (enterprise)", "Not configured"],
        ["SpyCloud", "$500+/mo", "Not configured"],
        ["Cybersixgill, KELA, DarkOwl, Flashpoint, Digital Shadows", "Enterprise pricing", "Not configured"],
    ]
    paid_rows = [[P("Tool", header=True), P("Tier / Cost", header=True), P("Status", header=True)]] + \
                [[P(a, True), P(b), P(c)] for a, b, c in paid_data]
    paid_table = Table(paid_rows, colWidths=[2.3*inch, 1.9*inch, 2.6*inch])
    paid_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7a3b1e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f1ee")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(paid_table)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "The tool is written so that adding any of these later only requires pasting in an API key -- "
        "no code changes needed.", small))

    # ── Country coverage ──
    story.append(Paragraph("Geographic Coverage", h2))
    story.append(Paragraph(
        f"Of {total:,} total findings, {country_total:,} carry a specific country/alliance "
        f"attribution (the remainder are labeled Global, Unknown, Cloud, Dark Web, or an orbital "
        f"owner code for satellite tracking data  -  categories that are not tied to one country "
        f"by nature of the source).", body))
    story.append(Spacer(1, 6))
    geo_rows = [["Country / Region", "Findings"]]
    for k in COUNTRY_KEYS:
        cnt = by_loc.get(k, 0)
        if cnt:
            geo_rows.append([k, f"{cnt:,}"])
    geo_table = Table(geo_rows, colWidths=[4.8*inch, 1.0*inch])
    geo_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f4f8")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]))
    story.append(geo_table)

    # ── Notable findings ──
    story.append(Paragraph("Notable Findings", h2))
    notables = [
        ("UK Ministry of Defence  -  exposed Git repository",
         "vle.action.mod.uk (a UK MoD e-learning platform) has a publicly accessible .git "
         "directory, revealing it runs Moodle. Cross-referenced against Shodan InternetDB, the "
         "exposed version matches 5 known CVEs. Severity: CRITICAL."),
        ("US Army  -  exposed .DS_Store directory listing",
         "fifeanddrum.army.mil exposes a macOS .DS_Store file revealing 18 internal folders. "
         "Observed repeatedly (91 separate scan events), indicating a persistent, unresolved "
         "exposure rather than a one-off."),
        ("US Army  -  exposed internal API documentation",
         "A public Swagger UI on an army.mil host lists live API endpoints, including "
         "delete-capable routes  -  a real exposed attack surface."),
        ("Dark web coverage",
         "Direct Tor (.onion) search returned genuine relevant results this cycle, including a "
         "forum thread referencing a Pentagon security leak."),
    ]
    for title_txt, desc in notables:
        story.append(Paragraph(f"<b>{title_txt}</b>", body))
        story.append(Paragraph(desc, body))
        story.append(Spacer(1, 8))

    # ── Methodology ──
    story.append(Paragraph("Methodology", h2))
    story.append(Paragraph(
        "Data is collected by an automated OSINT tool querying certificate transparency logs "
        "(crt.sh), internet-wide scanners (URLScan, LeakIX, ZoomEye, Onyphe, GrayHatWarfare), "
        "malware/threat-intel feeds (ThreatFox, MalwareBazaar, OTX AlienVault, CISA KEV, NVD, "
        "CIRCL), satellite tracking (Celestrak), dark web search (Torch via Tor), ransomware "
        "leak-site monitoring, Telegram OSINT channels, and defence news RSS. Every result "
        "passes through a shared relevance-filtering engine (domain allow-lists, contractor/APT "
        "name matching, and negative-term rejection) before being retained, and results are "
        "deduplicated against all prior collection runs.", body))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Paragraph(
        "This report reflects data collected via free/public and licensed OSINT sources only. "
        "No unauthorized access or exploitation was performed.", small))

    doc = SimpleDocTemplate(OUTPUT_PDF, pagesize=letter,
                             topMargin=0.6*inch, bottomMargin=0.6*inch,
                             leftMargin=0.7*inch, rightMargin=0.7*inch)
    doc.build(story)
    print(f"Report written to {OUTPUT_PDF}")


if __name__ == "__main__":
    build_report()
