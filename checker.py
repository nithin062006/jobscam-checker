"""Rule-based job-offer scam checker. Returns a risk score, level and reasons.

This is a heuristic helper, not proof. It must never say an offer is definitely
real or definitely fake.
"""
import re
from urllib.parse import quote

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


def analyze(text: str, company: str = "") -> dict:
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

    company = (company or "").strip()[:80] or extract_company(text)
    non_free = [d for d in domains if d not in FREE_MAIL]
    if company and non_free:
        token = re.sub(r"[^a-z0-9]", "", company.lower().split()[0])
        if len(token) >= 4 and not any(token in re.sub(r"[^a-z0-9]", "", d) for d in non_free):
            score += 10
            flags.append({
                "id": "domain_mismatch",
                "reason": f"Email domain ({non_free[0]}) doesn't seem to match the company name ({company}).",
                "advice": "Check the company's official website and compare the email domain exactly. Look-alike domains are common in scams.",
            })

    score = min(score, 100)
    if score >= 60:
        level, summary = "High", "Several strong scam signals. Treat this as likely fraudulent until independently verified."
    elif score >= 30:
        level, summary = "Medium", "Some warning signs. Verify the company and recruiter before sharing anything or paying."
    else:
        level, summary = "Low", "No major red flags found by this tool. That doesn't prove the offer is genuine, so still verify the company."

    types, steps = guidance({f["id"] for f in flags}, level)
    return {
        "score": score, "level": level, "summary": summary, "flags": flags,
        "types": types, "steps": steps,
        "verify": {"company": company, "domain": (non_free[0] if non_free else ""),
                   "links": verify_links(company, non_free[0] if non_free else "")},
    }


_COMPANY_SUFFIX = re.compile(
    r"\b([A-Z][\w&.\-]*(?:\s+[A-Z][\w&.\-]*){0,3}\s+"
    r"(?:Pvt\.?\s*Ltd\.?|Private\s+Limited|Limited|Ltd\.?|LLP|Inc\.?|Technologies|Solutions|Services|Corp\.?|Corporation))")
_COMPANY_AT = re.compile(r"\bat\s+([A-Z][\w&.\-]{2,}(?:\s+[A-Z][\w&.\-]{2,}){0,2})")
_STOP = {"The", "Our", "This", "Your", "Home", "Work", "Office"}


def extract_company(text: str) -> str:
    for rx in (_COMPANY_SUFFIX, _COMPANY_AT):
        m = rx.search(text)
        if m:
            name = m.group(1).strip(" .,-")
            if name and name.split()[0] not in _STOP:
                return name[:80]
    return ""


def verify_links(company: str, domain: str) -> list:
    links = []
    if company:
        q = quote(company)
        links += [
            {"label": f"Search \"{company}\" on LinkedIn", "url": f"https://www.linkedin.com/search/results/companies/?keywords={q}"},
            {"label": f"Search \"{company}\" with the word 'scam'", "url": f"https://www.google.com/search?q={quote(company + ' job offer scam fake')}"},
            {"label": f"Employee reviews of \"{company}\"", "url": f"https://www.google.com/search?q={quote(company + ' reviews ambitionbox glassdoor')}"},
        ]
    links.append({"label": "Check a company on the official MCA registry", "url": "https://www.mca.gov.in/content/mca/global/en/mca/master-data/MDS.html"})
    if domain:
        links.append({"label": f"Look up when {domain} was registered", "url": f"https://lookup.icann.org/en/lookup?name={quote(domain)}"})
    return links


_TYPE_INFO = {
    "fee": ("Advance-fee job scam", [
        "Do not pay any fee, deposit, or 'kit' charge. Genuine employers don't charge candidates.",
        "If you already paid, call 1930 immediately and tell your bank to try to block the transaction.",
        "Keep screenshots of chats, payment receipts, and phone numbers as evidence."]),
    "sensitive": ("Identity / bank data theft", [
        "Never share OTPs, UPI PIN, CVV, or banking passwords with anyone, including 'HR'.",
        "If you shared them, contact your bank right away and change passwords.",
        "Share Aadhaar/PAN only after verifying the company, and only for a real offer."]),
    "task_scam": ("Task / prepaid-task scam", [
        "Stop doing tasks and do not add money to 'unlock' higher earnings. The payouts are not real.",
        "Report the Telegram or WhatsApp account and file a complaint at cybercrime.gov.in.",
        "If you sent money, call 1930 at once."]),
    "easy_money": ("Too-good-to-be-true work-from-home offer", [
        "Compare the pay with market rates for that role. Very high pay for easy work is a warning sign.",
        "Ask for the official company email, website, and a video interview before going further."]),
    "messaging_only": ("Recruiter avoiding official channels", [
        "Ask for communication from an official company email and verify it on the company website.",
        "Don't join chat groups or click unknown links from the recruiter."]),
    "no_interview": ("Hiring without proper screening", [
        "A real job involves screening or an interview. An instant offer is a red flag."]),
    "free_email": ("Unofficial recruiter email", [
        "Check the recruiter on LinkedIn and confirm they work at the company."]),
    "domain_mismatch": ("Look-alike or mismatched email domain", [
        "Compare the email domain with the company's real website, character by character."]),
}


def guidance(ids: set, level: str):
    types, steps = [], []
    for key, (name, tips) in _TYPE_INFO.items():
        if key in ids:
            types.append(name)
            for t in tips:
                if t not in steps:
                    steps.append(t)
    if not steps:
        steps = ["Verify the company and the recruiter using the links below before sharing documents.",
                 "Never pay money to get a job, and never share OTPs or PINs."]
    return types, steps[:6]
