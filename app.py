import os
import re
import csv
import json
from datetime import datetime

import anthropic
from flask import Flask, request, jsonify
from flask_cors import CORS


app = Flask(__name__, static_url_path='', static_folder='static')
CORS(app)

# ── Anthropic client (set ANTHROPIC_API_KEY in your environment) ──────────────
_anthropic_client = None

def get_ai_client():
    global _anthropic_client
    if _anthropic_client is None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if api_key:
            _anthropic_client = anthropic.Anthropic(api_key=api_key)
    return _anthropic_client


# ──────────────────────────────────────────────────────────────────────────────
# EXISTING RULE-BASED DETECTION (unchanged)
# ──────────────────────────────────────────────────────────────────────────────

def detect_scam(text):
    text_lower = text.lower()
    score = 0
    reasons = []

    # ---------------- BASIC RULES ----------------

    # ---------------- LINK + MARKETING COMBO (VERY IMPORTANT) ----------------

    # Urgency
    if any(word in text_lower for word in ["urgent", "immediately", "act now", "final notice", "account blocked"]):
        score += 2
        reasons.append("Uses urgent or threatening language")

    # Links
    has_link = bool(re.search(r"https?://", text_lower))
    if has_link:
        score += 2
        reasons.append("Contains a link")

        if any(domain in text_lower for domain in [".xyz", ".top", "bit.ly", "tinyurl"]):
            score += 2
            reasons.append("Uses suspicious or shortened link")

    if has_link and any(word in text_lower for word in [
        "shop now", "buy now", "claim now", "click here", "limited offer"
    ]):
        score += 4
        reasons.append("Combines link with marketing pressure (high-risk pattern)")

    if "shop now" in text_lower:
        score += 2
        reasons.append("Encourages immediate purchase action")

    # Sensitive info
    if any(word in text_lower for word in ["otp", "password", "pin", "bank details", "cvv"]):
        score += 3
        reasons.append("Requests sensitive information")

    # Rewards
    if any(word in text_lower for word in ["winner", "lottery", "prize", "free money", "reward"]):
        score += 2
        reasons.append("Promises money or rewards")

    # Payment request
    if any(word in text_lower for word in ["send money", "transfer", "pay now", "deposit"]):
        score += 3
        reasons.append("Requests payment")

    # ---------------- EMAIL SCAM PATTERNS ----------------

    if any(word in text_lower for word in ["dear customer", "dear user", "valued customer"]):
        score += 2
        reasons.append("Generic greeting (phishing style)")

    if any(word in text_lower for word in [
        "verify your account", "unusual activity", "suspended account",
        "account limited", "security alert"
    ]):
        score += 2
        reasons.append("Mentions account security issue")

    if any(word in text_lower for word in [
        "click below", "login now", "confirm immediately", "update your details"
    ]):
        score += 2
        reasons.append("Pushes immediate action")

    if any(word in text_lower for word in [
        "inheritance", "beneficiary", "next of kin", "fund release", "unclaimed funds"
    ]):
        score += 4
        reasons.append("Mentions inheritance or unexpected funds")

    if re.search(r"[\w\.-]+@[\w\.-]+\.\w+", text):
        score += 3
        reasons.append("Contains email contact (common scam tactic)")

    if any(word in text_lower for word in [
        "further info", "more details", "contact for details"
    ]):
        score += 2
        reasons.append("Uses vague instructions")

    # ---------------- SMS / SPAM PATTERNS ----------------

    if any(word in text_lower for word in [
        "absa", "fnb", "standard bank", "nedbank", "capitec",
        "miway", "outsurance", "dialdirect", "king price"
    ]):
        score += 2
        reasons.append("Mentions financial/insurance brand (can be impersonated)")

    if "reply yes" in text_lower:
        score += 3
        reasons.append("User to reply YES (common scam tactic)")

    if any(word in text_lower for word in ["optout", "opt out", "no=out", "stop"]):
        score += 3
        reasons.append("Mass messaging / bulk SMS pattern")

    if any(word in text_lower for word in [
        "we would like to call", "discuss your", "offer you", "insurance options"
    ]):
        score += 2
        reasons.append("Unsolicited contact or offer")

    if any(word in text_lower for word in ["save", "low premium", "deal", "offer"]):
        score += 1
        reasons.append("Promotional persuasion language")

    if re.search(r"r\d+\s*(per day|/day)", text_lower):
        score += 2
        reasons.append("Uses attractive pricing bait")

    if re.match(r"^[a-z]+,", text_lower):
        score += 2
        reasons.append("Fake personalization (name-based spam)")

    # ---------------- COMBINATION LOGIC ----------------

    if has_link and "urgent" in text_lower:
        score += 2
        reasons.append("Combines urgency with a link")

    # ---------------- FINAL CLASSIFICATION ----------------

    if score >= 10:
        label = "SCAM"
    elif score >= 6:
        label = "SPAM"
    elif score >= 3:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"

    confidence = min(score * 10, 100)

    if confidence >= 81:
        risk = "HIGH"
    elif confidence >= 61:
        risk = "MEDIUM"
    elif confidence >= 31:
        risk = "LOW-MEDIUM"
    else:
        risk = "LOW"

    return label, confidence, risk, reasons


# ──────────────────────────────────────────────────────────────────────────────
# AI-POWERED ANALYSIS (Claude layer)
# ──────────────────────────────────────────────────────────────────────────────

AI_SYSTEM_PROMPT = """You are a cybersecurity expert specialising in scam, phishing, and spam detection for South African users.
Analyse the provided content and return ONLY a valid JSON object — no markdown, no extra text.

JSON schema (all fields required):
{
  "ai_score": <integer 0-100>,
  "ai_label": <"SAFE" | "SUSPICIOUS" | "SPAM" | "SCAM">,
  "ai_category": <"safe" | "phishing" | "smishing" | "spam" | "romance_scam" | "investment_fraud" | "lottery_scam" | "impersonation" | "advance_fee_fraud" | "other_scam">,
  "ai_flags": [<short strings describing specific red flags>],
  "ai_summary": <one plain-English sentence verdict>,
  "ai_action": <one sentence advice for the user>
}

Scoring:
  0–20   → safe
  21–40  → low risk
  41–60  → suspicious
  61–80  → likely scam
  81–100 → confirmed scam indicators

Focus on patterns common in South Africa: bank impersonation (ABSA, FNB, Capitec, Nedbank, Standard Bank),
SASSA/government grant fraud, job offer scams, WhatsApp prize scams, and insurance spam."""


def ai_analyse(text: str) -> dict | None:
    """
    Call Claude to analyse the text.
    Returns a dict with ai_* keys, or None if AI is unavailable.
    """
    client = get_ai_client()
    if not client:
        return None

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=800,
            system=AI_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Analyse this content:\n\n{text}"}],
        )
        raw = response.content[0].text.strip()
        # Strip accidental markdown fences
        raw = re.sub(r"^```json\s*|^```\s*|```$", "", raw, flags=re.MULTILINE).strip()
        return json.loads(raw)
    except Exception as e:
        print(f"[AI] Analysis failed: {e}")
        return None


def combine_results(
    rule_label: str,
    rule_confidence: int,
    rule_risk: str,
    rule_reasons: list[str],
    ai_result: dict | None,
) -> dict:
    """
    Merge rule-based and AI results into a single response.
    When AI is available, blend scores (40% rules, 60% AI).
    When AI is unavailable, fall back to rules only.
    """
    if ai_result is None:
        return {
            "label": rule_label,
            "confidence": rule_confidence,
            "risk": rule_risk,
            "reasons": rule_reasons,
            "ai_available": False,
            "ai_summary": None,
            "ai_flags": [],
            "ai_category": None,
            "ai_action": None,
        }

    # Blend confidence scores
    blended_score = int(rule_confidence * 0.4 + ai_result["ai_score"] * 0.6)
    blended_score = max(0, min(100, blended_score))

    # Final label: take the more severe of the two
    severity = {"SAFE": 0, "SUSPICIOUS": 1, "SPAM": 2, "SCAM": 3}
    rule_sev = severity.get(rule_label, 0)
    ai_sev = severity.get(ai_result["ai_label"], 0)
    final_label = rule_label if rule_sev >= ai_sev else ai_result["ai_label"]

    # Recalculate risk from blended score
    if blended_score >= 81:
        final_risk = "HIGH"
    elif blended_score >= 61:
        final_risk = "MEDIUM"
    elif blended_score >= 31:
        final_risk = "LOW-MEDIUM"
    else:
        final_risk = "LOW"

    # Merge reasons: keep rule reasons + add AI flags (deduplicated)
    all_reasons = list(rule_reasons)
    for flag in ai_result.get("ai_flags", []):
        if flag not in all_reasons:
            all_reasons.append(flag)

    return {
        "label": final_label,
        "confidence": blended_score,
        "risk": final_risk,
        "reasons": all_reasons,
        "ai_available": True,
        "ai_summary": ai_result.get("ai_summary"),
        "ai_flags": ai_result.get("ai_flags", []),
        "ai_category": ai_result.get("ai_category"),
        "ai_action": ai_result.get("ai_action"),
        # Keep individual scores for debugging / transparency
        "rule_confidence": rule_confidence,
        "ai_score": ai_result.get("ai_score"),
    }


# ──────────────────────────────────────────────────────────────────────────────
# SAVE HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def save_scan(text, label, confidence, risk, reasons, ai_summary=None):
    with open("scans.csv", "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            datetime.now(), text, label, confidence, risk,
            "; ".join(reasons),
            ai_summary or ""
        ])


def save_feedback(text, feedback):
    with open("feedback.csv", "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), text, feedback])


# ──────────────────────────────────────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    text = data.get("text", "")

    # Step 1: rule-based detection (fast, always runs)
    rule_label, rule_confidence, rule_risk, rule_reasons = detect_scam(text)

    # Step 2: AI analysis (runs when API key is set)
    ai_result = ai_analyse(text)

    # Step 3: combine into final verdict
    result = combine_results(rule_label, rule_confidence, rule_risk, rule_reasons, ai_result)

    # Save to CSV
    save_scan(
        text,
        result["label"],
        result["confidence"],
        result["risk"],
        result["reasons"],
        result.get("ai_summary"),
    )

    return jsonify(result)


@app.route("/feedback", methods=["POST"])
def feedback():
    data = request.json
    text = data.get("text")
    fb = data.get("feedback")
    save_feedback(text, fb)
    return jsonify({"status": "success"})


@app.route("/")
def home():
    return app.send_static_file("index.html")


if __name__ == "__main__":
    print("Anthropic API key loaded:", bool(os.getenv("ANTHROPIC_API_KEY")))
    app.run(debug=True)