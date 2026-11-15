"""Incident Report generator - turns the last analysis run into a PDF (ReportLab)."""
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

LEVEL_COLOR = {"SAFE": colors.HexColor("#16a34a"), "WARNING": colors.HexColor("#d97706"),
               "CRITICAL": colors.HexColor("#dc2626")}


def _table(rows, widths, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("FONT", (0, 0), (-1, -1), "Helvetica", 8.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                  ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                  ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5)]
    t.setStyle(TableStyle(style))
    return t


def build_pdf(run: dict, session: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm,
                            title="Ransomware Detection - Incident Report")
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontSize=17, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=5)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=colors.HexColor("#64748b"))
    cell = ParagraphStyle("c", parent=body, fontSize=8, leading=10)

    d, m, ml, lvl = run["detection"], run["detection"]["metrics"], run["ml"], run["final_level"]
    story = [
        Paragraph("Incident Report", h1),
        Paragraph("Ransomware Simulation &amp; Detection System", body),
        Paragraph(f"Generated {datetime.now():%d %b %Y, %H:%M} · Session {session[:8]} · "
                  "Educational simulation - all activity confined to the sandbox", small),
        Spacer(1, 8),
    ]

    verdict = Table([[Paragraph(f"<b>{lvl}</b>", ParagraphStyle("v", parent=body, fontSize=15,
                                                                textColor=colors.white)),
                      Paragraph(f"<b>{d['verdict']}</b><br/>Threat score {d['threat_score']}/100 · "
                                f"ML ransomware probability {ml['probability']*100:.0f}% · "
                                f"Scenario: {run['mode_label']}",
                                ParagraphStyle("v2", parent=body, textColor=colors.white))]],
                    colWidths=[32 * mm, 146 * mm])
    verdict.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), LEVEL_COLOR.get(lvl, colors.grey)),
                                 ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                 ("TOPPADDING", (0, 0), (-1, -1), 8),
                                 ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story += [verdict, Paragraph("Monitored metrics", h2)]

    story.append(_table([
        ["Metric", "Value", "Status"],
        ["Files in sandbox", m["total_files"], ""],
        ["File rename rate", f"{m['rename_rate']}% ({m['files_renamed']} files)", m["rename_status"]],
        ["Average entropy (before -> after)", f"{m['entropy_before']} -> {m['entropy_after']} / 8",
         m["entropy_status"]],
        ["Modification speed", f"{m['speed']} files/min", m["speed_status"]],
        ["Ransom notes found", ", ".join(m.get("ransom_notes", [])) or "None", ""],
        ["Activity duration", f"{m['duration_s']} s", ""],
        ["File-system events captured", f"{m['events_captured']} (via {m['metrics_source']})", ""],
    ], [70 * mm, 75 * mm, 33 * mm]))

    story.append(Paragraph("Detected patterns (heuristic rules)", h2))
    if d["patterns"]:
        story.append(_table([["Pattern", "Severity", "Points", "Evidence"]] +
                            [[Paragraph(p["name"], cell), p["severity"].upper(), f"+{p['points']}",
                              Paragraph(p["detail"], cell)] for p in d["patterns"]],
                            [52 * mm, 20 * mm, 14 * mm, 92 * mm]))
    else:
        story.append(Paragraph("No suspicious patterns detected.", body))

    story.append(Paragraph("Machine-learning assessment", h2))
    f = ml["features"]
    story.append(Paragraph(
        f"Decision Tree classifier: <b>{ml['label'].upper()}</b> with "
        f"{ml['probability']*100:.1f}% ransomware probability. Features used: rename rate "
        f"{f['rename_rate']}%, entropy after {f['entropy_after']}, entropy change {f['entropy_delta']}, "
        f"high-entropy ratio {f['high_entropy_ratio']}, log speed {f['log_speed']}, extension-change "
        f"ratio {f['ext_change_ratio']}, ransomware-extension ratio {f['ransom_ext_ratio']}.", body))

    story.append(Paragraph("Affected files", h2))
    if run["records"]:
        story.append(_table([["Original", "After", "Action", "Entropy"]] +
                            [[Paragraph(r["original"], cell), Paragraph(r["final"], cell),
                              Paragraph(r["action"], cell),
                              f"{r['entropy_before']:.2f} -> {r['entropy_after']:.2f}"]
                             for r in run["records"]],
                            [45 * mm, 52 * mm, 53 * mm, 28 * mm]))
    else:
        story.append(Paragraph("No files were changed.", body))

    story.append(Paragraph("Recommended response", h2))
    steps = {
        "CRITICAL": ["Isolate the affected machine from the network immediately.",
                     "Stop the offending process and preserve logs for investigation.",
                     "Do not pay any ransom - restore files from clean backups.",
                     "Report the incident to the security team / CERT-In."],
        "WARNING": ["Review the renamed or modified files and the process responsible.",
                    "Keep monitoring - escalate if entropy or speed rises.",
                    "Confirm recent backups are available."],
        "SAFE": ["No action needed. Activity matches normal user behaviour."],
    }[lvl]
    for i, s in enumerate(steps, 1):
        story.append(Paragraph(f"{i}. {s}", body))

    story.append(Paragraph("Event log (first 40 entries)", h2))
    story.append(_table([["Time", "Level", "Message"]] +
                        [[l["time"], l["level"], Paragraph(l["message"], cell)] for l in run["logs"][:40]],
                        [18 * mm, 20 * mm, 140 * mm]))

    doc.build(story)
    return buf.getvalue()
