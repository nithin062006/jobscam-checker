"""Compare the rule-based checker with ML models using cross-validation.

Usage:
  python ml/evaluate.py              # all rows (includes synthetic rows: only a smoke test)
  python ml/evaluate.py --real-only  # exclude source == synthetic (the honest number)

Needs: pip install -r requirements-ml.txt
Only ship a model if it beats the rules on --real-only with enough data
(aim for 150+ real messages, with plenty of genuine ones).
"""
import argparse
import csv
import sys
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import make_pipeline

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from checker import analyze  # noqa: E402


def load(real_only: bool):
    with (ROOT / "ml" / "data" / "messages.csv").open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if real_only:
        # Real = not machine-written (anything tagged synthetic* or hf_* is excluded).
        rows = [r for r in rows if "synthetic" not in r["source"] and not r["source"].startswith("hf_")]
    return [r["text"] for r in rows], np.array([1 if r["label"] == "scam" else 0 for r in rows])


def report(name, y, p, thr):
    pred = (p >= thr).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    try:
        auc = roc_auc_score(y, p)
    except ValueError:
        auc = float("nan")
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    print(f"{name:28s} P={pr:.2f} R={rc:.2f} F1={f1:.2f} AUC={auc:.2f}  false_alarms={fp}  missed_scams={fn}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real-only", action="store_true")
    args = ap.parse_args()

    x, y = load(args.real_only)
    n_scam, n_gen = int(y.sum()), int((1 - y).sum())
    print(f"messages: {len(y)}  (scam {n_scam}, genuine {n_gen})  real_only={args.real_only}")
    if min(n_scam, n_gen) < 5:
        sys.exit("Need at least 5 messages of each class to cross-validate.")
    if args.real_only and len(y) < 150:
        print("WARNING: fewer than 150 real messages. Treat these numbers as rough.")

    rules = np.array([analyze(t)["score"] / 100 if "score" in analyze(t) else 0 for t in x])
    report("rules (Medium+ = scam)", y, rules, 0.30)

    k = max(2, min(5, n_scam, n_gen))
    cv = StratifiedKFold(n_splits=k, shuffle=True, random_state=0)
    model = make_pipeline(
        TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True),
        LogisticRegression(max_iter=2000, class_weight="balanced"),
    )
    p = cross_val_predict(model, x, y, cv=cv, method="predict_proba")[:, 1]
    report("tfidf + logistic reg", y, p, 0.5)

    blend = 0.5 * rules + 0.5 * p
    report("rules + tfidf blend", y, blend, 0.4)


if __name__ == "__main__":
    main()
