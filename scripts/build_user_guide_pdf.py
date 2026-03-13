#!/usr/bin/env python3
"""Generate a polished end-user PDF guide for DIPS."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    Image,
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS_DIR = ROOT / "downloads"
OUTPUT_PDF = DOWNLOADS_DIR / "DIPS_User_Guide_v0.1.1.pdf"
SCREENSHOTS_DIR = ROOT / "screenshots"

PALETTE = {
    "navy": colors.HexColor("#0b1421"),
    "panel": colors.HexColor("#122033"),
    "cyan": colors.HexColor("#22bfd8"),
    "gold": colors.HexColor("#f8b84a"),
    "green": colors.HexColor("#35d1a3"),
    "ink": colors.HexColor("#16202a"),
    "muted": colors.HexColor("#5b6775"),
    "line": colors.HexColor("#d9e3eb"),
}


def _styles():
    base = getSampleStyleSheet()
    base["Title"].fontName = "Helvetica-Bold"
    base["Title"].fontSize = 28
    base["Title"].leading = 32
    base["Title"].textColor = PALETTE["navy"]
    base["Heading1"].fontName = "Helvetica-Bold"
    base["Heading1"].fontSize = 18
    base["Heading1"].leading = 22
    base["Heading1"].textColor = PALETTE["navy"]
    base["Heading1"].spaceBefore = 12
    base["Heading1"].spaceAfter = 8
    base["Heading2"].fontName = "Helvetica-Bold"
    base["Heading2"].fontSize = 13
    base["Heading2"].leading = 16
    base["Heading2"].textColor = PALETTE["panel"]
    base["Heading2"].spaceBefore = 10
    base["Heading2"].spaceAfter = 6
    base["BodyText"].fontName = "Helvetica"
    base["BodyText"].fontSize = 10.2
    base["BodyText"].leading = 14
    base["BodyText"].textColor = PALETTE["ink"]
    base["BodyText"].spaceAfter = 6
    base.add(
        ParagraphStyle(
        "DipsCode",
        parent=base["BodyText"],
        fontName="Courier",
        fontSize=8.6,
        leading=10.6,
        backColor=colors.HexColor("#eef5fa"),
        borderPadding=8,
        borderColor=PALETTE["line"],
        borderWidth=0.5,
        borderRadius=6,
        textColor=PALETTE["navy"],
        spaceBefore=4,
        spaceAfter=8,
        )
    )
    base.add(
        ParagraphStyle(
        "DipsCaption",
        parent=base["BodyText"],
        fontSize=8.5,
        leading=10,
        textColor=PALETTE["muted"],
        alignment=TA_CENTER,
        spaceBefore=4,
        spaceAfter=10,
        )
    )
    base.add(
        ParagraphStyle(
        "DipsCoverMeta",
        parent=base["BodyText"],
        alignment=TA_CENTER,
        textColor=PALETTE["muted"],
        fontSize=10,
        leading=13,
        )
    )
    base.add(
        ParagraphStyle(
        "DipsCallout",
        parent=base["BodyText"],
        backColor=colors.HexColor("#f6fbfd"),
        borderPadding=9,
        borderColor=PALETTE["cyan"],
        borderWidth=0.7,
        borderRadius=8,
        textColor=PALETTE["ink"],
        spaceBefore=4,
        spaceAfter=8,
        )
    )
    return base


STYLES = _styles()


def p(text: str, style: str = "BodyText") -> Paragraph:
    return Paragraph(text, STYLES[style])


def code_block(text: str) -> Preformatted:
    return Preformatted(text.strip(), STYLES["DipsCode"])


def bullet_list(items: list[str]) -> ListFlowable:
    return ListFlowable(
        [
            ListItem(Paragraph(item, STYLES["BodyText"]), leftIndent=8)
            for item in items
        ],
        bulletType="bullet",
        start="circle",
        leftIndent=16,
        bulletFontName="Helvetica-Bold",
        bulletColor=PALETTE["cyan"],
        spaceBefore=3,
        spaceAfter=6,
    )


def scaled_image(path: Path, max_width: float, max_height: float) -> Image:
    reader = ImageReader(str(path))
    width, height = reader.getSize()
    scale = min(max_width / width, max_height / height)
    image = Image(str(path), width=width * scale, height=height * scale)
    image.hAlign = "CENTER"
    return image


def captioned_image(path: Path, caption: str, max_height: float = 3.0 * inch) -> KeepTogether:
    return KeepTogether(
        [
            scaled_image(path, 6.7 * inch, max_height),
            Paragraph(caption, STYLES["DipsCaption"]),
        ]
    )


def section_table(rows: list[tuple[str, str]]) -> Table:
    table = Table(rows, colWidths=[1.95 * inch, 4.75 * inch], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PALETTE["navy"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("LEADING", (0, 0), (-1, -1), 11),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("TEXTCOLOR", (0, 1), (-1, -1), PALETTE["ink"]),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("BOX", (0, 0), (-1, -1), 0.6, PALETTE["line"]),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, PALETTE["line"]),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fbfd")]),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _cover_story() -> list:
    cover = [
        Spacer(1, 0.45 * inch),
        p("DIPS User Guide", "Title"),
        Spacer(1, 0.12 * inch),
        p("Digital Identity Protection System", "Heading2"),
        Spacer(1, 0.12 * inch),
        p(
            "Complete operator walkthrough for installation, first run, dashboard navigation, reports, downloads, and beta support.",
            "DipsCoverMeta",
        ),
        Spacer(1, 0.2 * inch),
        p("Version 0.1.1", "DipsCoverMeta"),
        p(f"Generated {date.today().isoformat()}", "DipsCoverMeta"),
        Spacer(1, 0.28 * inch),
        captioned_image(
            SCREENSHOTS_DIR / "dashboard-overview.png",
            "DIPS overview dashboard: the main command view for posture, alerts, trends, and timeline activity.",
            max_height=3.5 * inch,
        ),
        Spacer(1, 0.12 * inch),
        p(
            "This guide is written for first-time users, beta testers, and anyone downloading the Debian installer or source repository.",
            "DipsCallout",
        ),
        PageBreak(),
    ]
    return cover


def build_story() -> list:
    story: list = []
    story.extend(_cover_story())
    story.extend(
        [
            p("1. What DIPS Is", "Heading1"),
            p(
                "DIPS is a local-first digital identity defense platform. It focuses on exposure detection, credential hygiene, privacy risk, breach visibility, phishing analysis, browser posture, and report-driven triage.",
            ),
            bullet_list(
                [
                    "Use DIPS when you want to understand whether identity-related data, tokens, secrets, email samples, and browser posture create risk on a workstation.",
                    "Use the CLI for repeatable scans and automation.",
                    "Use the dashboard for investigation, review, screenshots, and a more guided visual workflow.",
                    "Use the reports when you need a shareable HTML artifact or JSON for further analysis.",
                ]
            ),
            p(
                "DIPS is not an antivirus. It does not quarantine malware or provide real-time signature scanning. It is built to surface identity risk and defensive posture instead.",
                "DipsCallout",
            ),
            p("2. What You Can Download", "Heading1"),
            section_table(
                [
                    ("Artifact", "Purpose"),
                    ("DIPS_User_Guide_v0.1.1.pdf", "This full usage guide. Share it with beta users and operators."),
                    ("dips_0.1.1_all.deb", "Debian-based installer for the CLI runtime with an optional GUI enablement step."),
                    ("dist/*.whl", "Python wheel for manual installation into a virtual environment."),
                    ("dist/*.tar.gz", "Source distribution for packaging or manual build flows."),
                ]
            ),
            Spacer(1, 0.12 * inch),
            p(
                "The Debian installer is intentionally lightweight. It installs the CLI runtime immediately. The desktop dashboard can be enabled afterward with a single helper command.",
                "BodyText",
            ),
            p("3. Install Options", "Heading1"),
            p("Source install from the repository:", "Heading2"),
            code_block(
                """
git clone <your-repo-url>
cd digital-identity-protection-system
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
                """
            ),
            p("Debian-based install from the packaged .deb:", "Heading2"),
            code_block(
                """
sudo dpkg -i downloads/dips_0.1.1_all.deb
dips --help
dips doctor
                """
            ),
            p(
                "To enable the desktop dashboard after installing the .deb, run:",
                "BodyText",
            ),
            code_block(
                """
sudo dips-enable-gui
dips-dashboard
                """
            ),
            p(
                "Important note: the GUI enablement step downloads PySide6 during installation. The base CLI runtime does not require that extra dependency.",
                "DipsCallout",
            ),
            PageBreak(),
            p("4. First Run Workflow", "Heading1"),
            bullet_list(
                [
                    "Step 1: Run `dips doctor` to validate Python, paths, caches, and plugin health.",
                    "Step 2: Run `dips scan --config config/example.config.json` for a real local scan.",
                    "Step 3: Open the HTML report in `reports/` or inspect the JSON report.",
                    "Step 4: Launch `dips dashboard` or `dips dashboard --load-report reports/<scan-id>.json`.",
                    "Step 5: Use the dashboard pages to review alerts, modules, reports, and settings.",
                ]
            ),
            p("Recommended first commands:", "Heading2"),
            code_block(
                """
dips doctor
dips scan --config config/example.config.json
dips dashboard --load-report reports/<scan-id>.json
                """
            ),
            p(
                "If you want a safe reproducible demo instead of scanning real files, use:",
                "BodyText",
            ),
            code_block(
                """
dips demo
dips dashboard --demo
                """
            ),
            p(
                "5. Core CLI Commands",
                "Heading1",
            ),
            section_table(
                [
                    ("Command", "What it does"),
                    ("`dips scan`", "Runs one full scan and writes reports."),
                    ("`dips watch`", "Repeats scans in the foreground on a schedule."),
                    ("`dips show-config`", "Prints the merged effective configuration."),
                    ("`dips doctor`", "Runs environment diagnostics for beta support and setup validation."),
                    ("`dips dashboard`", "Launches the desktop investigation surface."),
                    ("`dips demo`", "Generates safe synthetic reports and demo data."),
                ]
            ),
            Spacer(1, 0.1 * inch),
            p("Useful examples:", "Heading2"),
            code_block(
                """
dips scan --path ~/Documents --format json
dips scan --path ~/Documents --fail-on-severity high
dips watch --path ~/Documents --interval 300
dips show-config --config config/example.config.json
dips doctor --doctor-format json
                """
            ),
            p(
                "The policy options `--fail-on-severity` and `--fail-on-score` are useful when DIPS is part of an automated workflow. They still write reports before returning a non-zero exit code.",
                "BodyText",
            ),
            PageBreak(),
            p("6. How to Read the Console Results", "Heading1"),
            bullet_list(
                [
                    "Scan ID: the unique identifier for the current run.",
                    "Overall Risk: the combined score and label for the full posture.",
                    "Severity Counts: how many findings landed in each severity band.",
                    "Risk Categories: score slices such as token exposure, phishing risk, and browser risk.",
                    "Reports: the paths to the JSON and HTML artifacts written by the scan.",
                    "Top Findings and Correlated Patterns: the fastest way to understand what matters most.",
                ]
            ),
            p(
                "If the console output shows warnings, review them before deciding the scan is finished. Warnings often explain skipped modules, missing feeds, or environment limitations.",
            ),
            p("7. Reports: JSON and HTML", "Heading1"),
            bullet_list(
                [
                    "JSON is best for automation, integration, and loading reports back into the dashboard.",
                    "HTML is best for human review, sharing, and quick analyst walkthroughs.",
                    "Reports are redacted by default so they are safer to share during beta support or screenshot workflows.",
                ]
            ),
            captioned_image(
                SCREENSHOTS_DIR / "scan-report-view.png",
                "Reports page view: use this area to inspect exported artifacts and understand the top risk drivers.",
                max_height=3.05 * inch,
            ),
            p("Default output location:", "Heading2"),
            code_block(
                """
reports/
  <scan-id>.json
  <scan-id>.html
                """
            ),
            PageBreak(),
            p("8. Dashboard Tour", "Heading1"),
            p(
                "The dashboard has three main zones: a left sidebar, a top command bar, and the central page content.",
            ),
            captioned_image(
                SCREENSHOTS_DIR / "dashboard-overview.png",
                "Overview page: this is the default command view for posture, threat summary, correlations, and timeline review.",
                max_height=3.2 * inch,
            ),
            section_table(
                [
                    ("Area", "How to use it"),
                    ("Sidebar", "Click Overview, any detection module, Reports, or Settings to change pages."),
                    ("Top bar", "Use Run Scan to launch a scan and Open Reports to jump directly to the reports page."),
                    ("Overview cards", "Use these to read the protection score, alert totals, threat summary, and current posture at a glance."),
                    ("Timeline and alert queue", "Use these to prioritize what to investigate first."),
                ]
            ),
            p("9. Sidebar Navigation: What To Click", "Heading1"),
            bullet_list(
                [
                    "<b>Overview:</b> click this first to see the full risk posture, trend graph, severity heatmap, threat panel, and timeline.",
                    "<b>Detection Modules:</b> click a module page when you want findings only for that area such as Identity Exposure or Browser Security.",
                    "<b>Reports:</b> click here to open the latest JSON or HTML outputs and review top contributors.",
                    "<b>Settings:</b> click here to edit scan scope, output directory, report formats, data sources, and enabled modules.",
                ]
            ),
            p(
                "The dashboard is intentionally read-first. Start at Overview, then drill down into a module page only when you need focused evidence and remediation details.",
            ),
            captioned_image(
                SCREENSHOTS_DIR / "event-timeline.png",
                "Timeline view: use chronological events and correlations to understand how multiple risks connect during one scan.",
                max_height=2.9 * inch,
            ),
            PageBreak(),
            p("10. Module Pages", "Heading1"),
            bullet_list(
                [
                    "<b>Identity Exposure Monitor:</b> plaintext secrets, email addresses, JWT-like strings, and key material.",
                    "<b>Breach Exposure Alerts:</b> identifiers matched against offline datasets or approved provider lookups.",
                    "<b>Credential Security:</b> weak, reused, short, or identifier-derived passwords.",
                    "<b>Local Privacy Risk Scanner:</b> local exports, broad permissions, token files, and shell history exposure.",
                    "<b>Browser Security Audit:</b> risky settings, saved sessions, and extension sprawl.",
                    "<b>Phishing Analyzer:</b> suspicious links, auth failures, pressure language, and risky attachments.",
                    "<b>Threat Intelligence:</b> reputation results for URLs, domains, and IP indicators.",
                    "<b>AI Security Analysis:</b> plain-language summary, explanation, and remediation suggestions.",
                ]
            ),
            p(
                "Every module page shows a module posture area, module-specific metrics, a findings table, and remediation suggestions. If you only want to explain one risk class to a user, start on the relevant module page.",
            ),
            captioned_image(
                SCREENSHOTS_DIR / "threat-intelligence.png",
                "Threat intelligence page: review suspicious indicators and their reputation context here.",
                max_height=2.8 * inch,
            ),
            p("11. Reports Page", "Heading1"),
            bullet_list(
                [
                    "Click Reports in the sidebar.",
                    "Use the open buttons to launch the latest JSON or HTML artifacts.",
                    "Read the executive remediation section first, then the top risk drivers.",
                    "Use this page when you want a shareable output instead of live dashboard navigation.",
                ]
            ),
            p("12. Settings Page", "Heading1"),
            bullet_list(
                [
                    "Click Settings in the sidebar.",
                    "Set the output directory where reports should be written.",
                    "Tune max file size, max files, max workers, browser extension threshold, and watch interval.",
                    "Choose whether to redact evidence in reports.",
                    "Enable or disable approved breach lookups and online threat intelligence.",
                    "Select JSON and HTML output formats.",
                    "Add scan paths, email sample files, identity targets, breach datasets, threat feeds, and a password file.",
                    "Use Save Config As to write the current settings to a JSON config file.",
                ]
            ),
            PageBreak(),
            p("13. Suggested Workflows", "Heading1"),
            p("A. Quick health and first scan", "Heading2"),
            code_block(
                """
dips doctor
dips scan --config config/example.config.json
dips dashboard --load-report reports/<scan-id>.json
                """
            ),
            p("B. Reproducible demo for screenshots or walkthroughs", "Heading2"),
            code_block(
                """
dips demo
dips dashboard --demo
                """
            ),
            p("C. Scheduled foreground watch mode", "Heading2"),
            code_block(
                """
dips watch --path ~/Documents --interval 300
                """
            ),
            p("D. Automation gate for defensive workflows", "Heading2"),
            code_block(
                """
dips scan --path ~/Documents --fail-on-severity high
dips scan --path ~/Documents --fail-on-score 70
                """
            ),
            p("14. Troubleshooting", "Heading1"),
            bullet_list(
                [
                    "If a command does not start, run `dips doctor` first.",
                    "If the dashboard does not start after a .deb install, run `sudo dips-enable-gui` and then retry `dips-dashboard`.",
                    "If a report page is empty, confirm that a JSON report exists in the configured output directory.",
                    "If threat or breach modules seem quiet, confirm the relevant identifiers, datasets, or feed paths are configured.",
                    "If a beta issue needs support, capture redacted `dips doctor --doctor-format json` output and the scan ID.",
                ]
            ),
            p(
                "15. Security and Sharing Guidance",
                "Heading1",
            ),
            bullet_list(
                [
                    "Do not post raw secrets, tokens, or private keys in bug reports.",
                    "Prefer the HTML report for human sharing and the JSON report for automation.",
                    "Keep evidence redaction enabled unless you are doing a strictly private local review.",
                    "When in doubt, share the doctor output and a scan ID instead of the full raw file contents.",
                ]
            ),
            p(
                "16. Beta Feedback",
                "Heading1",
            ),
            p(
                "If you are using DIPS through the free beta, file feedback with the beta template in `.github/ISSUE_TEMPLATE/beta_feedback.md`. Include the operating system, DIPS version, the command you ran, and redacted doctor output if setup or runtime problems appear.",
            ),
            p(
                "You now have enough information to install DIPS, validate the environment, run scans, read the outputs, navigate the dashboard, and explain what the system can do to another user.",
                "DipsCallout",
            ),
        ]
    )
    return story


def _draw_header_footer(canvas, doc) -> None:
    canvas.saveState()
    width, height = LETTER
    canvas.setStrokeColor(PALETTE["line"])
    canvas.setLineWidth(0.6)
    canvas.line(doc.leftMargin, height - 0.52 * inch, width - doc.rightMargin, height - 0.52 * inch)
    canvas.line(doc.leftMargin, 0.55 * inch, width - doc.rightMargin, 0.55 * inch)
    canvas.setFillColor(PALETTE["muted"])
    canvas.setFont("Helvetica", 8)
    canvas.drawString(doc.leftMargin, 0.34 * inch, "DIPS User Guide v0.1.1")
    canvas.drawRightString(width - doc.rightMargin, 0.34 * inch, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def generate_pdf() -> Path:
    DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(OUTPUT_PDF),
        pagesize=LETTER,
        rightMargin=0.62 * inch,
        leftMargin=0.62 * inch,
        topMargin=0.78 * inch,
        bottomMargin=0.76 * inch,
        title="DIPS User Guide",
        author="Hackloi",
        subject="Installation and usage guide for DIPS",
    )
    doc.build(build_story(), onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)
    return OUTPUT_PDF


if __name__ == "__main__":
    path = generate_pdf()
    print(path)
