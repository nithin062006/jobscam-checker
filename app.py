import datetime as dt
import hmac
import json
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template, request

import contribute
from guides import GUIDES
import llm
from checker import analyze
from forensics import check_domain, valid_host
from telegram_bot import handle_update, send_message

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20_000  # small payloads only

FEEDBACK_FILE = Path(__file__).parent / "feedback.jsonl"
CONTACT_EMAIL = "vnaganithin@gmail.com"

# Simple in-memory per-IP rate limiting (resets on restart; fine for one small instance).
WINDOW_SECONDS = 600
LIMITS = {"check": 25, "feedback": 40, "forensics": 30, "ai": 8, "telegram": 20, "contribute": 10}
_hits = defaultdict(deque)

# Hard daily ceiling on AI calls so a burst of traffic can't run up a bill.
AI_DAILY_CAP = int(os.environ.get("AI_DAILY_CAP", "300"))
_ai_day = {"date": None, "count": 0}


def client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() or request.remote_addr or "unknown")


def rate_limited(bucket: str, who: str = None) -> bool:
    now = time.time()
    q = _hits[(bucket, who or client_ip())]
    while q and now - q[0] > WINDOW_SECONDS:
        q.popleft()
    if len(q) >= LIMITS[bucket]:
        return True
    q.append(now)
    if len(_hits) > 5000:  # keep memory bounded
        for k in [k for k, v in _hits.items() if not v or now - v[-1] > WINDOW_SECONDS]:
            _hits.pop(k, None)
    return False


def ai_budget_left() -> bool:
    today = dt.date.today().isoformat()
    if _ai_day["date"] != today:
        _ai_day.update(date=today, count=0)
    if _ai_day["count"] >= AI_DAILY_CAP:
        return False
    _ai_day["count"] += 1
    return True


@app.context_processor
def inject_globals():
    return {"contact_email": CONTACT_EMAIL, "ai_provider": llm.provider(), "contribute_on": contribute.enabled()}


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/scams")
def scams():
    return render_template("scams.html", guides=GUIDES)


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


@app.post("/api/forensics")
def forensics():
    if rate_limited("forensics"):
        return jsonify({"error": "Too many lookups. Please wait a few minutes."}), 429
    data = request.get_json(silent=True) or {}
    hosts = [str(h).lower().strip()[:253] for h in (data.get("domains") or [])][:3]
    return jsonify({"results": [check_domain(h) for h in hosts if valid_host(h.removeprefix("www."))]})


@app.post("/api/ai")
def ai():
    if not llm.provider():
        return jsonify({"error": "AI analysis isn't enabled on this site."}), 404
    if rate_limited("ai"):
        return jsonify({"error": "Too many AI analyses in a short time. Please wait a few minutes."}), 429
    if not ai_budget_left():
        return jsonify({"error": "The AI analysis limit for today has been reached. Try again tomorrow."}), 503
    data = request.get_json(silent=True) or {}
    # Only sent to the AI provider because the user ticked the opt-in box; never stored here.
    result = llm.analyze_ai(str(data.get("text", ""))[:4000])
    if result is None:
        return jsonify({"error": "The AI analysis is unavailable right now."}), 502
    return jsonify(result)


@app.post("/telegram/webhook")
def telegram_webhook():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    secret = os.environ.get("TELEGRAM_WEBHOOK_SECRET")
    if not token or not secret:
        return "", 404
    sent = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not hmac.compare_digest(sent, secret):
        return "", 403
    update = request.get_json(silent=True) or {}
    chat = ((update.get("message") or update.get("edited_message") or {}).get("chat") or {}).get("id")
    if chat is not None and rate_limited("telegram", f"tg:{chat}"):
        return "ok"
    handle_update(update, lambda chat_id, text: send_message(token, chat_id, text))
    return "ok"


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


@app.post("/api/contribute")
def contribute_route():
    if not contribute.enabled():
        return jsonify({"error": "Contributions are not switched on."}), 503
    if rate_limited("contribute"):
        return jsonify({"error": "Too many submissions. Try again later."}), 429
    d = request.get_json(silent=True) or {}
    if d.get("consent") is not True:
        return jsonify({"error": "Please confirm you are happy to share this message."}), 400
    row, err = contribute.prepare(d.get("text", ""), d.get("label", ""), d.get("level", ""), d.get("score"))
    if err:
        return jsonify({"error": err}), 400
    if not contribute.store(row):
        return jsonify({"error": "Could not save right now. Please try again later."}), 502
    return jsonify({"ok": True})


@app.get("/guide/<slug>")
def guide(slug):
    g = GUIDES.get(slug)
    if not g:
        abort(404)
    return render_template("guide.html", g=g, slug=slug, guides=GUIDES)


@app.get("/googlec66a0bfb5bc18d3d.html")
def google_verify():
    return Response("google-site-verification: googlec66a0bfb5bc18d3d.html", mimetype="text/html")


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nAllow: /\nDisallow: /api/\nSitemap: " + request.url_root.rstrip("/") + "/sitemap.xml\n", mimetype="text/plain")


@app.get("/sitemap.xml")
def sitemap():
    base = request.url_root.rstrip("/")
    paths = ["/", "/scams", "/privacy"] + ["/guide/" + s for s in GUIDES]
    body = "".join(f"<url><loc>{base}{p}</loc></url>" for p in paths)
    return Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + body + "</urlset>", mimetype="application/xml")


@app.get("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(debug=True, port=5000)
