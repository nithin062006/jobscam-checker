"""Rule-based job-offer scam checker. Returns a risk score, level and reasons.

This is a heuristic helper, not proof. It must never say an offer is definitely
real or definitely fake.
"""
import re

FREE_MAIL = ("gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com", "rediffmail.com", "proton.me", "protonmail.com")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "goo.gl", "is.gd", "shorturl.at")

# (id, weight, regex, reason, advice)
RULES = [
    ("fee", 40,
     r"(registration|processing|security|refundable|training|kit|laptop|onboarding|verification|interview|document|joining)\s*(fee|fees|charge|charges|deposit|amount)|pay\s+(rs\.?|₹|inr)\s*[\d,]+|(rs\.?|₹)\s*[\d,]+\s*(as|for)\s+(registration|security|processing|training|kit)",
     "Asks you to pay money (fee/deposit/kit) to get the job.",
     "Real employers do not charge candidates. Do not pay."),
    ("sensitive", 25,
     r"\b(otp|cvv|upi\s*pin|atm\s*pin|net\s*banking|bank\s*(account\s*)?(details|password)|aadhaar\s*(number|card)?|pan\s*card)\b.*\b(send|share|provide|submit|upload)\b|\b(send|share|provide|submit|upload)\b.*\b(otp|cvv|upi\s*pin|atm\s*pin|bank\s*(account\s*)?details|aadhaar|pan\s*card)\b",
     "Asks for sensitive details (OTP, PIN, bank, Aadhaar/PAN) before any real hiring process.",
     "Never share OTPs or PINs. Share ID documents only after verifying the company."),
    ("messaging_only", 18,
     r"(contact|message|msg|chat|reach|apply|join)[^.\n]{0,40}(whatsapp|telegram|signal)|(whatsapp|telegram)[^.\n]{0,40}(only|directly|number|group|channel)",
     "Moves the conversation to WhatsApp/Telegram instead of official email or a company portal.",
     "Ask for an official company email and verify it on the company website."),
    ("task_scam", 35,
     r"(like|subscribe|rate|review|follow)[^.\n]{0,30}(and|&)\s*(earn|get paid)|earn\s*(rs\.?|₹|inr)?\s*[\d,]+\s*(per|/|a)\s*(day|hour|task|video|order)|(prepaid|recharge)\s*task|(youtube|google\s*maps|amazon)\s*(review|rating)s?\s*(job|task|work)",
     "Looks like a 'task' scam (earn money for likes/reviews/tasks).",
     "These are a common scam pattern. Do not deposit money to 'unlock' tasks."),
    ("easy_money", 22,
     r"(work\s*from\s*home|part[\s-]?time|data\s*entry|typing)[^.\n]{0,60}(earn|salary|income)[^.\n]{0,30}(\d{2,3},?\d{3}|lakh)|(earn|income)\s*(up\s*to\s*)?(rs\.?|₹)?\s*\d{2,3},?\d{3}\s*(per|/|a)\s*(week|month|day)|no\s*(experience|skills?|interview)\s*(needed|required|necessary)[^.\n]{0,60}(salary|earn|income|pay)",
     "Promises high pay for little or no work or experience.",
     "Compare the pay with the market rate for that role. Very high pay for easy work is a warning sign."),
    ("no_interview", 18,
     r"(direct|instant|immediate)\s*(selection|joining|hiring|offer)|selected\s*without\s*(an\s*)?interview|no\s*interview|offer\s*letter\s*(within|in)\s*\d+\s*(hours?|mins?)",
     "Offers a job without a proper interview process.",
     "Genuine hiring usually involves screening and an interview."),
    ("urgency", 12,
     r"(limited|few)\s*(seats|slots|vacancies|positions)|(apply|reply|confirm|pay)[^.\n]{0,20}(today|immediately|urgently|within\s*\d+\s*(hours?|mins?))|last\s*date\s*(is\s*)?(today|tomorrow)|hurry",
     "Creates urgency or pressure to act fast.",
     "Take time to verify. Pressure is a common tactic."),
    ("generic_greeting", 6,
     r"^(dear\s+(candidate|applicant|sir|madam|job\s*seeker)|hello\s+candidate)",
     "Uses a generic greeting instead of your name.",
     "Check whether the sender knows anything specific about you or your application."),
]


def _emails(text):
    return re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", text.lower())


def _urls(text):
    return re.findall(r"https?://([^\s/]+)", text.lower())


def analyze(text: str) -> dict:
    text = (text or "").strip()
    if len(text) < 20:
        return {"error": "Paste the full message or offer text (at least a couple of sentences)."}

    low = text.lower()
    score = 0
    flags = []

    for rid, weight, pattern, reason, advice in RULES:
        if re.search(pattern, low, flags=re.IGNORECASE | re.MULTILINE):
            score += weight
            flags.append({"id": rid, "reason": reason, "advice": advice})

    domains = _emails(low)
    free = [d for d in domains if d in FREE_MAIL]
    if free:
        score += 15
        flags.append({
            "id": "free_email",
            "reason": f"Recruiter contact uses a free email domain ({free[0]}).",
            "advice": "Established companies usually email from their own domain. Verify the person and company on LinkedIn or the official site.",
        })

    short = [d for d in _urls(low) if d in SHORTENERS]
    if short:
        score += 10
        flags.append({
            "id": "shortened_link",
            "reason": f"Contains a shortened link ({short[0]}) that hides the destination.",
            "advice": "Do not click shortened links in job messages. Ask for the official careers page.",
        })

    score = min(score, 100)
    if score >= 60:
        level, summary = "High", "Several strong scam signals. Treat this as likely fraudulent until independently verified."
    elif score >= 30:
        level, summary = "Medium", "Some warning signs. Verify the company and recruiter before sharing anything or paying."
    else:
        level, summary = "Low", "No major red flags found by this tool. That doesn't prove the offer is genuine, so still verify the company."

    return {"score": score, "level": level, "summary": summary, "flags": flags}
