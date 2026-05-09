import os
import re
import csv
import json
from datetime import datetime

from google import genai
from flask import Flask, request, jsonify
from flask_cors import CORS


app = Flask(__name__, static_url_path='', static_folder='static')
CORS(app)

# ── Gemini client (set GEMINI_API_KEY in your environment) ────────────────────
_gemini_model = None

def get_ai_model():
    global _gemini_model
    if _gemini_model is None:
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key:
            _gemini_model = genai.Client(api_key=api_key)
    return _gemini_model


# ──────────────────────────────────────────────────────────────────────────────
# RULE-BASED DETECTION
# ──────────────────────────────────────────────────────────────────────────────

def detect_scam(text):
    text_lower = text.lower()
    score = 0
    reasons = []

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

    # Email scam patterns
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

    if re.search(r"[\w.-]+@[\w.-]+\.\w+", text):
        score += 3
        reasons.append("Contains email contact (common scam tactic)")

    if any(word in text_lower for word in ["further info", "more details", "contact for details"]):
        score += 2
        reasons.append("Uses vague instructions")

    # SMS / spam patterns
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

    if has_link and "urgent" in text_lower:
        score += 2
        reasons.append("Combines urgency with a link")

    # Final classification
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
# AI ANALYSIS (Gemini layer)
# ──────────────────────────────────────────────────────────────────────────────

AI_PROMPT_TEMPLATE = """You are a cybersecurity expert specialising in scam, phishing, and spam detection for South African users.
Analyse the content below and return ONLY a valid JSON object — no markdown, no extra text, no backticks.

JSON schema (all fields required):
{{
  "ai_score": <integer 0-100>,
  "ai_label": <"SAFE" or "SUSPICIOUS" or "SPAM" or "SCAM">,
  "ai_category": <"safe" or "phishing" or "smishing" or "spam" or "romance_scam" or "investment_fraud" or "lottery_scam" or "impersonation" or "advance_fee_fraud" or "other_scam">,
  "ai_flags": [<short strings describing specific red flags>],
  "ai_summary": <one plain-English sentence verdict>,
  "ai_action": <one sentence advice for the user>
}}

Scoring guide:
  0-20   = safe
  21-40  = low risk
  41-60  = suspicious
  61-80  = likely scam
  81-100 = confirmed scam indicators

Focus on patterns common in South Africa: bank impersonation (ABSA, FNB, Capitec, Nedbank, Standard Bank),
SASSA/government grant fraud, job offer scams, WhatsApp prize scams, and insurance spam.

Content to analyse:
{text}"""


def ai_analyse(text: str):
    client = get_ai_model()
    if not client:
        print("[AI] No client — API key missing")
        return None

    try:
        prompt = AI_PROMPT_TEMPLATE.format(text=text)
        response = client.models.generate_content(
            model="models/gemini-2.0-flash-lite",
            contents=prompt
        )
        print("[AI] Raw response:", response.text)
        raw = response.text.strip()
        raw = re.sub(r"^```json\s*|^```\s*|```$", "", raw, flags=re.MULTILINE).strip()
        print("[AI] Cleaned:", raw)
        result = json.loads(raw)
        print("[AI] Parsed OK:", result)
        return result
    except Exception as e:
        print(f"[AI] Gemini analysis failed: {e}")
        return None


def combine_results(rule_label, rule_confidence, rule_risk, rule_reasons, ai_result):
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

    # Blend confidence scores: 40% rules + 60% AI
    blended_score = int(rule_confidence * 0.4 + ai_result["ai_score"] * 0.6)
    blended_score = max(0, min(100, blended_score))

    # Final label: take the more severe of the two
    severity = {"SAFE": 0, "SUSPICIOUS": 1, "SPAM": 2, "SCAM": 3}
    final_label = rule_label if severity.get(rule_label, 0) >= severity.get(ai_result["ai_label"], 0) else ai_result["ai_label"]

    # Recalculate risk from blended score
    if blended_score >= 81:
        final_risk = "HIGH"
    elif blended_score >= 61:
        final_risk = "MEDIUM"
    elif blended_score >= 31:
        final_risk = "LOW-MEDIUM"
    else:
        final_risk = "LOW"

    # Merge reasons + AI flags (deduplicated)
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

    # Step 2: Gemini AI analysis (runs when API key is set)
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
    print("Gemini API key loaded:", bool(os.getenv("GEMINI_API_KEY")))
    app.run(debug=True)