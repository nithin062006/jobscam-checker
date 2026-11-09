"""Train the TF-IDF + logistic regression model on all rows and save it.

Usage: python ml/train.py [--real-only]
Output: ml/model.joblib (small). The app ignores it unless ENABLE_ML=1.
Do not enable it in production until evaluate.py --real-only shows it helps.
"""
import argparse
import csv
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

ROOT = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real-only", action="store_true")
    args = ap.parse_args()
    with (ROOT / "data" / "messages.csv").open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if args.real_only:
        rows = [r for r in rows if "synthetic" not in r["source"] and not r["source"].startswith("hf_")]
    x = [r["text"] for r in rows]
    y = [1 if r["label"] == "scam" else 0 for r in rows]
    model = make_pipeline(
        TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True),
        LogisticRegression(max_iter=2000, class_weight="balanced"),
    ).fit(x, y)
    joblib.dump(model, ROOT / "model.joblib")
    print(f"Trained on {len(y)} messages ({sum(y)} scam). Saved ml/model.joblib")


if __name__ == "__main__":
    main()
