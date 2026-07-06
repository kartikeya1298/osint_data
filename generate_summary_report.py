"""
generate_summary_report.py
Builds a PDF summary report of military_osint_master.csv, scoped to India and
its neighbouring countries (India, Pakistan, China, Bangladesh, Nepal, Sri
Lanka, Myanmar) -- total findings, category/severity/source breakdowns, and
an appendix listing the actual search terms/tags/queries used by each API
source. Run: python generate_summary_report.py
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

# Report scope: India and its neighbouring countries only. Matched against
# the "location" field by substring (catches "Orbit - India" satellite rows
# too) plus exact short ISO-code matches (some sources record just "IN"/"PK").
NEIGHBOR_NAMES = ["India", "Pakistan", "China", "Bangladesh", "Nepal", "Sri Lanka", "Myanmar"]
NEIGHBOR_CODES = {"IN", "PK", "CN", "PRC", "BD", "NP", "LK", "MM"}


def is_neighbor_row(location: str) -> bool:
    loc = (location or "").strip()
    if loc in NEIGHBOR_CODES:
        return True
    return any(name in loc for name in NEIGHBOR_NAMES)


def load_rows():
    with open(MASTER_CSV, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def build_report():
    all_rows = load_rows()
    rows = [r for r in all_rows if is_neighbor_row(r.get("location"))]
    total = len(rows)
    total_all = len(all_rows)

    by_cat = Counter(r.get("category_code") for r in rows)
    by_sev = Counter(r.get("severity") for r in rows)
    by_conf = Counter(r.get("confidence") for r in rows)
    by_layer = Counter(r.get("source_layer") for r in rows)
    by_source = Counter(r.get("source") for r in rows)
    by_loc = Counter(r.get("location") for r in rows)
    distinct_sources = len(by_source)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=22, spaceAfter=6)
    subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=11,
                                     textColor=colors.HexColor("#555555"), spaceAfter=18)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=18, spaceAfter=8,
                         textColor=colors.HexColor("#1a1a2e"))
    body = ParagraphStyle("BodyCustom", parent=styles["Normal"], fontSize=10, leading=14)
    small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=8.5,
                            textColor=colors.HexColor("#777777"))
    cell_style = ParagraphStyle("Cell", parent=body, fontSize=9, leading=11.5)
    cell_style_bold = ParagraphStyle("CellBold", parent=cell_style, fontName="Helvetica-Bold")
    header_style = ParagraphStyle("HeaderCell", parent=cell_style_bold, textColor=colors.white)

    def P(text, bold=False, header=False):
        style = header_style if header else (cell_style_bold if bold else cell_style)
        return Paragraph(text, style)

    def styled_table(rows_data, col_widths, header_color):
        t = Table(rows_data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_color)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f4f8")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    story = []

    # ── Title ──
    story.append(Paragraph("Military Cyber Threat OSINT", title_style))
    story.append(Paragraph("Intelligence Summary Report -- India & Neighbouring Countries", subtitle_style))
    story.append(Paragraph(
        f"Generated {datetime.now().strftime('%B %d, %Y')} &nbsp;|&nbsp; "
        f"Data source: <b>military_osint_master.csv</b>", small))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc"), spaceBefore=8, spaceAfter=16))

    # ── Scope note ──
    if total_all > total:
        scope_text = (
            f"<b>Scope:</b> this report covers India, Pakistan, China, Bangladesh, Nepal, Sri Lanka, "
            f"and Myanmar only. Of {total_all:,} total findings in the full dataset, {total:,} "
            f"({total*100/total_all:.1f}%) carry a location attribution to one of these countries -- "
            f"the rest (other countries, plus non-country-specific categories like Global threat-intel "
            f"feeds, Cloud, or Dark Web) are excluded from the tables below."
        )
    else:
        scope_text = (
            f"<b>Scope:</b> this dataset has been filtered to India, Pakistan, China, Bangladesh, "
            f"Nepal, Sri Lanka, and Myanmar only -- all {total:,} findings below are from these "
            f"countries. Other countries' data has been removed from the master dataset."
        )
    story.append(Paragraph(scope_text, body))
    story.append(Spacer(1, 10))

    # ── Executive summary ──
    story.append(Paragraph("Executive Summary", h2))
    summary_data = [
        ["Findings in scope (India + neighbours)", f"{total:,}"],
        ["Distinct data sources contributing to this scope", f"{distinct_sources}"],
        ["Countries covered", "India, Pakistan, China, Bangladesh, Nepal, Sri Lanka, Myanmar"],
        ["CRITICAL-severity findings", f"{by_sev.get('CRITICAL', 0):,}"],
        ["HIGH-confidence findings", f"{by_conf.get('HIGH', 0):,}" + (f"  ({by_conf.get('HIGH',0)*100//total}% of scope)" if total else "")],
    ]
    summary_rows = [[P(label, True), P(value)] for label, value in summary_data]
    t = Table(summary_rows, colWidths=[3.0*inch, 3.4*inch])
    t.setStyle(TableStyle([
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#eeeeee")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)

    # ── Category breakdown ──
    story.append(Paragraph("Breakdown by Threat Category", h2))
    cat_rows = [["Code", "Category", "Count", "% of Scope"]]
    for code, name in CATEGORY_NAMES.items():
        cnt = by_cat.get(code, 0)
        pct = f"{cnt*100/total:.1f}%" if total else "0.0%"
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

    # ── Per-country breakdown ──
    story.append(Paragraph("Findings by Country", h2))
    geo_rows = [["Country", "Findings"]]
    for name in NEIGHBOR_NAMES:
        cnt = sum(v for k, v in by_loc.items() if name in k)
        geo_rows.append([name, f"{cnt:,}"])
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

    # ── Severity / confidence / layer breakdown ──
    story.append(Paragraph("Severity, Confidence & Source-Layer Distribution", h2))
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_rows = [["Severity", "Count", "%"]] + [
        [s, f"{by_sev.get(s,0):,}", f"{by_sev.get(s,0)*100/total:.1f}%" if total else "0.0%"] for s in sev_order
    ]
    conf_rows = [["Confidence", "Count", "%"]] + [
        [c, f"{by_conf.get(c,0):,}", f"{by_conf.get(c,0)*100/total:.1f}%" if total else "0.0%"] for c in ["HIGH", "MEDIUM", "LOW"]
    ]
    layer_rows = [["Layer", "Count", "%"]] + [
        [l, f"{by_layer.get(l,0):,}", f"{by_layer.get(l,0)*100/total:.1f}%" if total else "0.0%"]
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

    # ── Sources contributing to this scope ──
    story.append(Paragraph("Data Sources Contributing to This Scope", h2))
    src_rows = [["Source", "Findings"]]
    for src, cnt in by_source.most_common(25):
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

    # ── Notable findings ──
    story.append(Paragraph("Notable Findings", h2))
    notables = [
        ("Indian Navy -- active wildcard certificate",
         "A currently-valid (not expired, expires Feb 2027) wildcard TLS certificate for "
         "*.indiannavy.gov.in was found via certificate transparency logs. A wildcard "
         "certificate covers every subdomain under the domain -- if its private key were ever "
         "compromised, an attacker could impersonate any indiannavy.gov.in subdomain. Severity: CRITICAL."),
        ("Indian Ministry of Defence -- expired wildcard certificates",
         "Two expired wildcard certificates were found for *.mod.gov.in and a specific "
         "subdomain, *.maabharatikesapoot.mod.gov.in. Expired wildcard certs on government "
         "infrastructure indicate stale or unmanaged TLS configuration. Severity: CRITICAL."),
        ("AVIC (China) -- active wildcard certificate",
         "A currently-valid wildcard certificate for *.sadri.avic.com was found -- AVIC "
         "(Aviation Industry Corporation of China) is a major Chinese state-owned defence and "
         "aerospace conglomerate. Severity: CRITICAL."),
        ("Sri Lanka Army -- two active wildcard certificates",
         "Currently-valid wildcard certificates were found for *.army.lk and *.cloud.army.lk "
         "(expiring November 2026 and January 2027 respectively). Severity: CRITICAL."),
        ("Sri Lanka Navy -- active wildcard certificate",
         "A currently-valid wildcard certificate for *.navy.lk was found, expiring December 2026. "
         "Severity: CRITICAL."),
        ("Myanmar Ministry of Defence -- active wildcard certificate",
         "A currently-valid wildcard certificate for *.mod.gov.mm was found, expiring December "
         "2026. Severity: CRITICAL."),
        ("Bangladesh Ministry of Defence -- exposed live credential in a Git config file",
         "An exposed .git/config file on mod.gov.bd revealed a live GitLab access token granting "
         "write access to a contractor's private repository (\"oracle-cloud-npf-ministrycluster\"), "
         "which by its name appears to be Oracle Cloud infrastructure for a government ministry "
         "cluster. This is one of the most significant findings in this report -- a real, working "
         "credential, not just metadata. The token has been redacted from the underlying dataset "
         "and this report; it is not published anywhere. This should be reported to the affected "
         "organization so the credential can be revoked."),
    ]
    for title_txt, desc in notables:
        story.append(Paragraph(f"<b>{title_txt}</b>", body))
        story.append(Paragraph(desc, body))
        story.append(Spacer(1, 8))

    story.append(PageBreak())

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
        "deduplicated against all prior collection runs. The appendix below lists every search "
        "term, domain, and tag actually queried across all sources (not limited to this report's "
        "country scope), so the full search methodology is transparent.", body))

    story.append(PageBreak())

    # ── Appendix: search terms / tags used per source ──
    story.append(Paragraph("Appendix: Search Terms & Tags Used Per Source", h2))
    story.append(Paragraph(
        "The tool does not use generic keyword searches (e.g. just \"military\") -- every source "
        "below is queried with specific domains, named organizations/APT groups, or technical "
        "tags. This list covers every country the tool tracks, not just the ones in this report's "
        "scope, so the full methodology is visible.", body))
    story.append(Spacer(1, 8))

    appendix_head = ParagraphStyle("ApxHead", parent=body, fontName="Helvetica-Bold",
                                    fontSize=10.5, spaceBefore=12, spaceAfter=4,
                                    textColor=colors.HexColor("#1a1a2e"))

    story.append(Paragraph("Domain / host-based sources", appendix_head))
    story.append(Paragraph(
        "crt.sh, URLScan.io, LeakIX, GrayHatWarfare, Hudson Rock, Onyphe, ZoomEye, "
        "BreachDirectory, GitHub code search, and SecurityTrails all query variations of this "
        "same master domain list (exact official domains, never bare TLDs like \".gov\" or "
        "\".mil.xx\" alone, to avoid matching unrelated civilian sites):", body))
    story.append(Spacer(1, 4))

    domain_groups = [
        ("United States", "army.mil, navy.mil, af.mil, marines.mil, disa.mil, socom.mil, "
                           "cybercom.mil, dia.mil, nsa.gov, dod.gov, nato.int"),
        ("United Kingdom", "mod.uk"),
        ("Germany", "bundeswehr.de"),
        ("Canada", "forces.gc.ca"),
        ("Australia", "defence.gov.au"),
        ("India", "indianarmy.nic.in, indiannavy.gov.in, indianairforce.nic.in, "
                  "mod.gov.in, drdo.gov.in"),
        ("Pakistan", "pakistanarmy.gov.pk, paknavy.gov.pk, paf.gov.pk, mod.gov.pk, ispr.gov.pk"),
        ("China", "mod.gov.cn, norinco.cn, spacechina.com, avic.com, cetc.com.cn"),
        ("Israel", "mod.gov.il, idf.il"),
        ("France", "defense.gouv.fr"),
        ("Japan", "mod.go.jp"),
        ("South Korea", "mnd.go.kr, army.mil.kr"),
        ("Taiwan", "mnd.gov.tw"),
        ("Ukraine", "mod.gov.ua, zsu.gov.ua, gur.gov.ua"),
        ("Bangladesh", "mod.gov.bd, afd.gov.bd, ispr.gov.bd"),
        ("Nepal", "mod.gov.np, nepalarmy.mil.np"),
        ("Sri Lanka", "defence.lk, army.lk, navy.lk, airforce.lk"),
        ("Myanmar", "mod.gov.mm"),
        ("Defence contractors", "lockheedmartin.com, rtx.com, northropgrumman.com, "
                                 "baesystems.com, leidos.com, l3harris.com, generaldynamics.com, "
                                 "rafael.co.il, iai.co.il, dassault-aviation.com, naval-group.com"),
        ("Indian defence PSUs", "hal-india.co.in, bel-india.in, bdl-india.com, mazagondock.in, "
                                 "grse.in, bemlindia.in"),
    ]
    domain_rows = [[P("Country / Group", header=True), P("Domains Queried", header=True)]] + \
                  [[P(c, True), P(d)] for c, d in domain_groups]
    story.append(styled_table(domain_rows, [1.7*inch, 5.1*inch], "#1f6f43"))

    story.append(Paragraph("GitHub code-search dork patterns", appendix_head))
    story.append(Paragraph(
        "Beyond the domain list above, GitHub search additionally scopes by leaked-file patterns: "
        "<font face='Courier'>filename:.env</font>, <font face='Courier'>filename:config.json</font>, "
        "<font face='Courier'>filename:config.yaml</font>, <font face='Courier'>filename:secrets.yaml</font>, "
        "<font face='Courier'>filename:application.properties</font>, <font face='Courier'>filename:kubeconfig</font>, "
        "<font face='Courier'>filename:.htpasswd</font>, <font face='Courier'>extension:pem</font>, "
        "<font face='Courier'>extension:key</font>, <font face='Courier'>extension:sql</font>, "
        "<font face='Courier'>extension:tf</font> -- combined with the domain list and terms like "
        "<font face='Courier'>api_key</font>, <font face='Courier'>token</font>, "
        "<font face='Courier'>secret</font>, <font face='Courier'>password</font>. Any hit is then "
        "content-verified (the actual file is fetched and checked for a real secret-shaped pattern) "
        "before being marked CRITICAL.", body))

    story.append(Paragraph("Malware / threat-intel feeds (tag- and family-based)", appendix_head))
    threat_rows = [
        ["ThreatFox (abuse.ch)", "Named APT/nation-state malware families: Cobalt Strike, Turla, Sandworm, "
                                  "NotPetya, Industroyer, Fancy Bear/APT28, Cozy Bear/APT29, Lazarus, Kimsuky, "
                                  "Winnti/APT41, Volt Typhoon, Salt Typhoon, ShadowPad, PlugX, Transparent "
                                  "Tribe/APT36, SideCopy, Mustang Panda/APT40 -- OR explicit tags "
                                  "apt / nation-state / targeted / military."],
        ["MalwareBazaar (abuse.ch)", "Tag queries: APT, RAT, loader, stealer, plus recent submissions -- gated "
                                      "on the same named-APT-family list as ThreatFox (Cobalt Strike, Turla, "
                                      "Sandworm, APT28/29/41, Lazarus, Kimsuky, ShadowPad, PlugX, Transparent "
                                      "Tribe, SideCopy, Mustang Panda, etc.)."],
        ["OTX AlienVault", "Pulse search tags: military, apt, nation-state, defence, espionage."],
        ["NVD (CVE database)", "Vendor/product keywords: Cisco IOS XE, Fortinet FortiGate, Palo Alto PAN-OS, "
                                "Juniper JunOS, F5 BIG-IP, Siemens SIMATIC, Rockwell Studio 5000, Honeywell "
                                "Experion, Schneider Modicon, GE CIMPLICITY, SCADA/industrial control, "
                                "satellite GPS firmware, Ivanti Pulse Secure, VMware vCenter -- CVSS >= 9.0 only."],
        ["CIRCL CVE API", "Vendor terms: Cisco, Fortinet, Palo Alto, Juniper, F5, Pulse Secure, Ivanti, "
                           "SonicWall, Citrix, Siemens, Rockwell, Honeywell, Schneider Electric, Viasat, "
                           "Hughes, Iridium, Inmarsat, plus others -- CVSS >= 9.0 only."],
        ["CISA KEV", "Word-boundary regex: scada, ics, industrial, defence, defense, military, "
                      "critical infrastructure, plc, ot."],
    ]
    threat_data = [[P("Source", header=True), P("Tags / Filter Criteria", header=True)]] + \
                  [[P(a, True), P(b)] for a, b in threat_rows]
    story.append(styled_table(threat_data, [1.6*inch, 5.2*inch], "#7a3b1e"))

    story.append(Paragraph("Dark web, satellite, and other structural sources", appendix_head))
    other_rows = [
        ["Torch (.onion dark web search)", "army.mil credentials, nato classified leak, pentagon hack "
                                            "breach, military apt nation state, defense contractor "
                                            "database, dod.gov exploit -- each result additionally "
                                            "passed through the same relevance-filtering engine."],
        ["Telegram (public channels)", "English keywords: missile, classified, breach, espionage, cyber "
                                        "attack, nato, hack, intercept, warfare, pentagon, special forces, "
                                        "radar, sigint; Russian-language word-stems (added after finding "
                                        "English-only keywords meant Russian-language channels like rybar "
                                        "could never score a match): raket- (missile), sekretn- (secret/"
                                        "classified), utechk- (leak), kiberatak- (cyberattack), nato, vzlom "
                                        "(hack), spetsnaz (special forces), radar, razvedk- (intelligence/"
                                        "reconnaissance), atak- (attack), armiya (army), flot (navy/fleet), "
                                        "oruzhi- (weapon), voyna (war)."],
        ["Celestrak (satellite tracking)", "Object-name match: GPS, GLONASS, COSMOS; owner-code match: "
                                            "PRC (China), CIS/RU/USSR (Russia), US, IND (India) -- deliberately "
                                            "not extended to other countries where military-vs-civilian "
                                            "satellite names can't yet be reliably distinguished."],
        ["OpenSky Network (GPS/EW)", "Geographic regions monitored: Eastern Europe (Ukraine/Russia), Middle "
                                      "East (Israel/Lebanon/Syria), Baltic Region, Black Sea, South Asia "
                                      "(India/Pakistan/China border), Taiwan Strait, Korean Peninsula."],
        ["ransomware.live", "Named ransomware groups: LockBit, ALPHV/BlackCat, Clop, RansomHub, Akira, "
                             "Play, RagnarLocker, Rhysida, Medusa, Qilin, and others -- cross-referenced "
                             "against the same military-domain and defence-contractor lists above."],
    ]
    other_data = [[P("Source", header=True), P("Tags / Filter Criteria", header=True)]] + \
                 [[P(a, True), P(b)] for a, b in other_rows]
    story.append(styled_table(other_data, [1.6*inch, 5.2*inch], "#3a3a5e"))

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
