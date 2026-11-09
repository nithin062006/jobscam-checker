import json
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from checker import analyze

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20_000  # small payloads only

FEEDBACK_FILE = Path(__file__).parent / "feedback.jsonl"
CONTACT_EMAIL = "vnaganithin@gmail.com"

# Simple in-memory per-IP rate limiting (resets on restart; fine for one small instance).
WINDOW_SECONDS = 600
LIMITS = {"check": 25, "feedback": 40}
_hits = defaultdict(deque)


def client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() or request.remote_addr or "unknown")


def rate_limited(bucket: str) -> bool:
    now = time.time()
    q = _hits[(bucket, client_ip())]
    while q and now - q[0] > WINDOW_SECONDS:
        q.popleft()
    if len(q) >= LIMITS[bucket]:
        return True
    q.append(now)
    if len(_hits) > 5000:  # keep memory bounded
        for k in [k for k, v in _hits.items() if not v or now - v[-1] > WINDOW_SECONDS]:
            _hits.pop(k, None)
    return False


@app.context_processor
def inject_globals():
    return {"contact_email": CONTACT_EMAIL}


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/scams")
def scams():
    return render_template("scams.html")


@app.get("/privacy")
def privacy():
    return render_template("privacy.html")


@app.post("/api/check")
def check():
    if rate_limited("check"):
        return jsonify({"error": "Too many checks in a short time. Please wait a few minutes and try again."}), 429
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", ""))[:8000]
    company = str(data.get("company", ""))[:80]
    # The submitted text is analysed in memory and never stored.
    return jsonify(analyze(text, company))


@app.post("/api/feedback")
def feedback():
    if rate_limited("feedback"):
        return jsonify({"ok": False}), 429
    data = request.get_json(silent=True) or {}
    entry = {
        "t": int(time.time()),
        "helpful": bool(data.get("helpful")),
        "level": str(data.get("level", ""))[:10],
    }
    with FEEDBACK_FILE.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    return jsonify({"ok": True})


@app.get("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(debug=True, port=5000)
