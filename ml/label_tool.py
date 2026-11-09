"""Add real, labeled messages to ml/data/messages.csv.

Usage:  python ml/label_tool.py
Paste a message, finish with a line containing only END, then pick a label.

Privacy: phone numbers are replaced with [PHONE] and the part before @ in email
addresses is replaced with [user] (the domain is kept because it is a useful
signal). Names, company-internal details and links are NOT scrubbed, so edit the
text yourself before pasting. Only add messages you are allowed to share.
"""
import csv
import re
import sys
from pathlib import Path

DATA = Path(__file__).parent / "data" / "messages.csv"


def scrub(text: str) -> str:
    text = re.sub(r"\+?\d[\d\s\-]{8,}\d", "[PHONE]", text)
    text = re.sub(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", r"[user]@\1", text)
    return " ".join(text.split())


def existing() -> set:
    if not DATA.exists():
        return set()
    with DATA.open(newline="", encoding="utf-8") as f:
        return {" ".join(r["text"].split()).lower() for r in csv.DictReader(f)}


def main():
    seen = existing()
    print(f"{len(seen)} messages so far. Ctrl+C to quit.\n")
    while True:
        print("Paste message, then a line with END:")
        lines = []
        for line in sys.stdin:
            if line.strip() == "END":
                break
            lines.append(line.rstrip("\n"))
        text = scrub("\n".join(lines))
        if len(text) < 20:
            print("Too short, skipped.\n")
            continue
        if text.lower() in seen:
            print("Duplicate, skipped.\n")
            continue
        print("\nScrubbed text:\n" + text + "\n")
        label = input("Label: [s]cam or [g]enuine (anything else = skip): ").strip().lower()
        if label not in ("s", "g"):
            print("Skipped.\n")
            continue
        source = input("Source (e.g. friend, reddit, own_inbox, advisory): ").strip() or "unknown"
        new = not DATA.exists()
        with DATA.open("a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["text", "label", "source"])
            w.writerow([text, "scam" if label == "s" else "genuine", source])
        seen.add(text.lower())
        print(f"Saved. Total: {len(seen)}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye.")
