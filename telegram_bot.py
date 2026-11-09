"""Telegram bot logic. The Flask app receives updates on a secret webhook and calls handle_update().

Setup: create a bot with @BotFather, set TELEGRAM_BOT_TOKEN and TELEGRAM_WEBHOOK_SECRET on the
server, then run `python telegram_setup.py` once to register the webhook.
"""
import requests

from checker import analyze

HELP = (
    "Hi! Forward or paste a job offer or recruiter message and I'll check it for common scam signs.\n\n"
    "Your message is analysed and not stored. Results come from simple rules and can be wrong, "
    "so always verify the company yourself and never pay to get a job.\n\n"
    "If you lost money, call 1930 and report at cybercrime.gov.in."
)


def format_reply(result: dict) -> str:
    if "error" in result:
        return result["error"]
    lines = [f"Risk: {result['level']} ({result['score']}/100)", result["summary"]]
    if result["flags"]:
        lines.append("\nWarning signs:")
        lines += [f"• {f['reason']}" for f in result["flags"][:6]]
    if result["steps"]:
        lines.append("\nWhat to do:")
        lines += [f"{i}. {s}" for i, s in enumerate(result["steps"][:4], 1)]
    lines.append("\nNot a verdict: this tool can miss scams or flag real offers. Verify on the company's official website.")
    return "\n".join(lines)[:3900]


def send_message(token: str, chat_id, text: str):
    try:
        requests.post(f"https://api.telegram.org/bot{token}/sendMessage", timeout=8,
                      json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True})
    except Exception:
        pass


def handle_update(update: dict, send) -> bool:
    """Process one Telegram update. `send(chat_id, text)` delivers the reply. Returns True if replied."""
    msg = update.get("message") or update.get("edited_message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    if chat_id is None:
        return False
    text = (msg.get("text") or msg.get("caption") or "").strip()
    if msg.get("photo") and not text:
        send(chat_id, "I can only read text for now. Please paste the message text.")
        return True
    if text.startswith(("/start", "/help")):
        send(chat_id, HELP)
        return True
    send(chat_id, format_reply(analyze(text[:4000])))
    return True
