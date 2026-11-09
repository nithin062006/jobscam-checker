"""Opt-in message donation. Scrubs personal details, then stores one row in Supabase.

Needs SUPABASE_URL and SUPABASE_ANON_KEY. The table allows INSERT only for the anon
role (see supabase_setup.sql), so a leaked key cannot read anyone's submissions.
"""
import hashlib
import os
import re

import requests

LABELS = {"scam", "genuine", "unsure"}
MIN_LEN, MAX_LEN = 40, 4000


def enabled() -> bool:
    return bool(os.environ.get("SUPABASE_URL") and os.environ.get("SUPABASE_ANON_KEY"))


def scrub(text: str) -> str:
    text = re.sub(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", r"[user]@\1", text)       # email local part
    text = re.sub(r"\b[A-Z]{5}\d{4}[A-Z]\b", "[PAN]", text)                     # PAN
    text = re.sub(r"\b\d{4}\s?\d{4}\s?\d{4}\b", "[ID]", text)                   # Aadhaar-like
    text = re.sub(r"(?i)\b(otp|pin|cvv)\b\D{0,12}\d{3,8}", r"\1 [CODE]", text)  # codes
    text = re.sub(r"\+?\d[\d\s\-]{8,}\d", "[PHONE]", text)                      # phone / long numbers
    text = re.sub(r"\b\d{9,18}\b", "[NUMBER]", text)                            # account numbers
    return " ".join(text.split())


def prepare(text: str, label: str, level: str = "", score=None):
    """Return (row, error)."""
    if label not in LABELS:
        return None, "Pick what you think this message is."
    clean = scrub(text or "")
    if len(clean) < MIN_LEN:
        return None, "That message is too short to be useful."
    clean = clean[:MAX_LEN]
    row = {
        "text": clean,
        "user_label": label,
        "tool_level": str(level)[:10],
        "tool_score": int(score) if isinstance(score, (int, float)) else None,
        "text_hash": hashlib.sha256(clean.lower().encode()).hexdigest(),
    }
    return row, None


def store(row: dict) -> bool:
    url = os.environ["SUPABASE_URL"].rstrip("/") + "/rest/v1/contributions"
    key = os.environ["SUPABASE_ANON_KEY"]
    try:
        r = requests.post(url, json=row, timeout=8, headers={
            "apikey": key, "Authorization": f"Bearer {key}",
            "Content-Type": "application/json", "Prefer": "return=minimal"})
    except requests.RequestException:
        return False
    return r.status_code in (200, 201, 204, 409)  # 409 = duplicate hash, already have it
