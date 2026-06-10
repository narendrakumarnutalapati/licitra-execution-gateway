import io
from datetime import datetime, timezone
from uuid import uuid4

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch


def generate_evidence_json(verification_result: dict, mmr_result: dict) -> dict:
    proof = mmr_result.get("proof")
    if isinstance(proof, dict):
        proof_size = len(proof.get("siblings", []))
    else:
        proof_size = 0

    return {
        "evidence_id": str(uuid4()),
        "intent_id": verification_result.get("intent_id", "unknown"),
        "decision_id": verification_result.get("decision_id", "unknown"),
        "ticket_id": verification_result.get("ticket_id", "unknown"),
        "agent_id": verification_result.get("agent_id", "unknown"),
        "action": verification_result.get("action", "unknown"),
        "resource": verification_result.get("resource", "unknown"),
        "decision": "ALLOWED" if verification_result.get("allowed") else "BLOCKED",
        "reason": verification_result.get("reason", "unknown"),
        "diff": verification_result.get("diff", None),
        "schema_violations": verification_result.get("schema_violations", None),
        "injection_findings": verification_result.get("injection_findings", None),
        "payload_hash": verification_result.get("payload_hash", "unknown"),
        "ticket_hash": verification_result.get("ticket_hash", "unknown"),
        "mmr_leaf_index": mmr_result.get("leaf_index"),
        "mmr_leaf_hash": mmr_result.get("leaf_hash"),
        "mmr_root": mmr_result.get("root_hash"),
        "mmr_proof": proof,
        "mmr_proof_size": proof_size,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def generate_evidence_pdf(evidence_dict: dict) -> bytes:
    try:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter,
                                rightMargin=inch, leftMargin=inch,
                                topMargin=inch, bottomMargin=inch)
        styles = getSampleStyleSheet()
        story = []

        # 1. Header
        story.append(Paragraph("LICITRA Evidence Report", styles["Title"]))
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph(f"Evidence ID: {evidence_dict.get('evidence_id', '')}", styles["Normal"]))
        story.append(Paragraph(f"Created At: {evidence_dict.get('created_at', '')}", styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        # 2. Decision
        decision = evidence_dict.get("decision", "UNKNOWN")
        if decision == "ALLOWED":
            dec_color = colors.Color(0, 0.6, 0)
        else:
            dec_color = colors.Color(0.8, 0, 0)
        dec_style = ParagraphStyle("Decision", parent=styles["Heading1"], textColor=dec_color, fontSize=20)
        story.append(Paragraph(decision, dec_style))
        story.append(Spacer(1, 0.2 * inch))

        # 3. Identifiers table
        story.append(Paragraph("Identifiers", styles["Heading2"]))
        id_data = [
            ["intent_id", str(evidence_dict.get("intent_id", ""))],
            ["decision_id", str(evidence_dict.get("decision_id", ""))],
            ["ticket_id", str(evidence_dict.get("ticket_id", ""))],
            ["agent_id", str(evidence_dict.get("agent_id", ""))],
        ]
        id_table = Table(id_data, colWidths=[1.5 * inch, 4.5 * inch])
        id_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ]))
        story.append(id_table)
        story.append(Spacer(1, 0.2 * inch))

        # 4. Action Details
        story.append(Paragraph("Action Details", styles["Heading2"]))
        action_data = [
            ["action", str(evidence_dict.get("action", ""))],
            ["resource", str(evidence_dict.get("resource", ""))],
            ["reason", str(evidence_dict.get("reason", ""))],
        ]
        action_table = Table(action_data, colWidths=[1.5 * inch, 4.5 * inch])
        action_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ]))
        story.append(action_table)
        story.append(Spacer(1, 0.2 * inch))

        # 5. OWASP Finding
        story.append(Paragraph("OWASP Finding", styles["Heading2"]))
        reason = evidence_dict.get("reason", "")
        if "INJECTION" in reason:
            owasp = "LLM01 - Prompt Injection"
        elif "SCHEMA" in reason:
            owasp = "LLM05 - Improper Output Handling"
        elif "RATE_LIMIT" in reason:
            owasp = "LLM10 - Unbounded Consumption"
        else:
            owasp = "LLM06 - Excessive Agency"
        story.append(Paragraph(owasp, styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        # 6. Diff Section (only if diff is not None)
        diff = evidence_dict.get("diff")
        if diff is not None:
            story.append(Paragraph("Payload Diff", styles["Heading2"]))
            red_style = ParagraphStyle("RedNormal", parent=styles["Normal"], textColor=colors.red)
            if isinstance(diff, dict):
                for k, v in diff.items():
                    story.append(Paragraph(f"{k}: {v}", red_style))
            else:
                story.append(Paragraph(str(diff), red_style))
            story.append(Spacer(1, 0.2 * inch))

        # 7. MMR Proof Section
        story.append(Paragraph("MMR Audit Proof", styles["Heading2"]))
        story.append(Paragraph(f"Leaf Index: {evidence_dict.get('mmr_leaf_index', '')}", styles["Normal"]))
        story.append(Paragraph(f"Leaf Hash: {evidence_dict.get('mmr_leaf_hash', '')}", styles["Normal"]))
        story.append(Paragraph(f"MMR Root: {evidence_dict.get('mmr_root', '')}", styles["Normal"]))
        mmr_proof = evidence_dict.get("mmr_proof")
        if isinstance(mmr_proof, dict):
            siblings = mmr_proof.get("siblings", [])
            for i, s in enumerate(siblings):
                story.append(Paragraph(f"Sibling[{i}]: {s}", styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        # 8. Footer
        story.append(Paragraph("Generated by LICITRA Execution Gateway", styles["Normal"]))

        doc.build(story)
        return buf.getvalue()

    except Exception:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter)
        styles = getSampleStyleSheet()
        doc.build([Paragraph("LICITRA Evidence Report", styles["Title"])])
        return buf.getvalue()
