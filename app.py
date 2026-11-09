import json
import time
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from checker import analyze

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20_000  # small payloads only

FEEDBACK_FILE = Path(__file__).parent / "feedback.jsonl"


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/check")
def check():
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", ""))[:8000]
    # The submitted text is analysed in memory and never stored.
    return jsonify(analyze(text))


@app.post("/api/feedback")
def feedback():
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
