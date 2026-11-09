"""Register the Telegram webhook once. Usage:

  TELEGRAM_BOT_TOKEN=... TELEGRAM_WEBHOOK_SECRET=... SITE_URL=https://jobscam-checker.onrender.com \
  python telegram_setup.py

The secret is sent back by Telegram in a header on every update, and the app rejects
requests without it. Use a long random value (letters, digits, _ and - only).
"""
import os
import sys

import requests

token = os.environ.get("TELEGRAM_BOT_TOKEN")
secret = os.environ.get("TELEGRAM_WEBHOOK_SECRET")
site = os.environ.get("SITE_URL", "").rstrip("/")
if not (token and secret and site.startswith("https://")):
    sys.exit("Set TELEGRAM_BOT_TOKEN, TELEGRAM_WEBHOOK_SECRET and SITE_URL (https://...).")

r = requests.post(f"https://api.telegram.org/bot{token}/setWebhook", timeout=15,
                  json={"url": f"{site}/telegram/webhook", "secret_token": secret,
                        "allowed_updates": ["message", "edited_message"]})
print(r.status_code, r.text)
