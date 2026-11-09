from checker import analyze

SCAM = """Dear Candidate, You are selected without interview for work from home data entry.
Earn Rs 40,000 per month. Pay Rs 2,500 registration fee today to confirm your joining.
Contact on WhatsApp only. Email hr.company@gmail.com. Limited seats, apply immediately."""

TASK = "Like and earn Rs 500 per task. Join our Telegram group now. Prepaid task unlocks higher pay."

REAL = """Hi Priya, thanks for applying for the Backend Engineer role at Acme Corp.
We'd like to schedule a 30-minute call with our engineering manager next week.
Please share your availability. You can reach me at recruiter@acmecorp.com."""


def test_scam_is_high():
    r = analyze(SCAM)
    assert r["level"] == "High", r
    ids = {f["id"] for f in r["flags"]}
    assert {"fee", "free_email", "messaging_only"} <= ids


def test_task_scam_flagged():
    r = analyze(TASK)
    assert any(f["id"] == "task_scam" for f in r["flags"]), r
    assert r["level"] in ("Medium", "High")


def test_normal_offer_is_low():
    r = analyze(REAL)
    assert r["level"] == "Low", r


def test_short_input_rejected():
    assert "error" in analyze("hi")
