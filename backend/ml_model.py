"""ML-based Detection (PBL-3).

A Decision Tree classifier that looks at the same behavioural features as the
heuristic engine and predicts the probability that the activity is ransomware.

Why a Decision Tree?
  - Works well on small, tabular feature sets.
  - Fully explainable: we can print the exact if/else rules it learned
    (important for an educational tool and for the viva).

Training data:
  Real ransomware samples cannot be used in an academic setting, so the model is
  trained on a SYNTHETIC behavioural dataset generated from activity profiles
  (normal editing, photo renaming, zip/backup compression, fast ransomware,
  slow "stealthy" ransomware). Hard benign cases (bulk renaming, compression that
  raises entropy) are included on purpose so the model cannot rely on one feature.
"""
import json
import math
import os
import time

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier, export_text

FEATURES = [
    "rename_rate",         # % of files renamed (0-100)
    "entropy_after",       # average entropy after activity (0-8)
    "entropy_delta",       # average change in entropy
    "high_entropy_ratio",  # share of files rewritten with entropy >= 7.5
    "log_speed",           # log10(1 + files modified per minute)
    "ext_change_ratio",    # share of files whose extension changed
    "ransom_ext_ratio",    # share of files with .locked/.enc/... extensions
]

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(os.path.dirname(HERE), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "decision_tree.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")

_model = None


# ---------------------------------------------------------------- dataset
def _profile(rng, kind):
    u = rng.uniform
    if kind == "normal_edit":
        return [u(0, 10), u(3, 7.9), u(-0.3, 0.3), 0.0, math.log10(1 + u(0, 120)), u(0, 0.1), 0.0], 0
    if kind == "bulk_rename":      # e.g. photo organiser renaming IMG_001 -> Trip_001
        return [u(50, 100), u(3, 7.95), u(-0.05, 0.05), 0.0, math.log10(1 + u(30, 3000)),
                u(0, 0.4), 0.0], 0
    if kind == "compression":      # zipping / backing up files raises entropy
        return [u(0, 30), u(7.4, 8.0), u(1.0, 4.0), u(0.2, 1.0), math.log10(1 + u(5, 400)),
                u(0.2, 1.0), 0.0], 0
    if kind == "fast_ransomware":
        return [u(75, 100), u(7.8, 8.0), u(1.0, 4.5), u(0.8, 1.0), math.log10(1 + u(200, 6000)),
                u(0.75, 1.0), u(0.7, 1.0)], 1
    if kind == "user_encryption":  # a user encrypting 1-2 files with a legit tool (.enc/.gpg)
        share = u(0.02, 0.25)
        return [share * 100, u(5.0, 7.9), u(0.3, 2.5), share, math.log10(1 + u(1, 40)),
                share, share * (1 if rng.random() < 0.5 else 0)], 0
    if kind == "stealth_ransomware":  # slow; ~half encrypt in place without renaming
        if rng.random() < 0.5:
            ren, ext, rext = u(0, 15), 0.0, 0.0
        else:
            ren = u(40, 100)
            ext = ren / 100 * u(0.7, 1.0)
            rext = ext * u(0.3, 1.0)
        return [ren, u(7.6, 8.0), u(0.8, 4.5), u(0.5, 1.0), math.log10(1 + u(3, 250)),
                ext, rext], 1
    raise ValueError(kind)


def generate_dataset(n=4000, seed=42, noise=0.03):
    rng = np.random.default_rng(seed)
    kinds = ["normal_edit", "bulk_rename", "compression", "user_encryption",
             "fast_ransomware", "stealth_ransomware"]
    X, y = [], []
    for i in range(n):
        feats, label = _profile(rng, kinds[i % len(kinds)])
        if rng.random() < noise:        # label noise -> more realistic accuracy
            label = 1 - label
        X.append(feats)
        y.append(label)
    return np.array(X), np.array(y)


# ---------------------------------------------------------------- training
def train(save=True):
    X, y = generate_dataset()
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=7, stratify=y)
    # ---- compare three classic models on the same split ----
    candidates = {
        "Decision Tree": DecisionTreeClassifier(max_depth=4, min_samples_leaf=20, random_state=7),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=6, random_state=7),
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000)),
    }
    comparison = []
    for name, clf in candidates.items():
        t0 = time.perf_counter()
        clf.fit(X_tr, y_tr)
        train_ms = (time.perf_counter() - t0) * 1000
        p = clf.predict(X_te)
        comparison.append({
            "model": name,
            "accuracy": round(float(accuracy_score(y_te, p)), 4),
            "precision": round(float(precision_score(y_te, p)), 4),
            "recall": round(float(recall_score(y_te, p)), 4),
            "f1": round(float(f1_score(y_te, p)), 4),
            "train_ms": round(train_ms, 1),
            "explainable": name != "Random Forest",
        })

    model = candidates["Decision Tree"]   # chosen: accurate AND explainable
    pred = model.predict(X_te)
    metrics = {
        "model": "DecisionTreeClassifier(max_depth=4)",
        "train_samples": int(len(X_tr)),
        "test_samples": int(len(X_te)),
        "accuracy": round(float(accuracy_score(y_te, pred)), 4),
        "confusion_matrix": confusion_matrix(y_te, pred).tolist(),
        "report": classification_report(y_te, pred, target_names=["benign", "ransomware"],
                                        output_dict=True),
        "feature_importance": {f: round(float(v), 4)
                               for f, v in zip(FEATURES, model.feature_importances_)},
        "rules": export_text(model, feature_names=FEATURES, decimals=2),
        "comparison": comparison,
    }
    if save:
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        with open(METRICS_PATH, "w") as f:
            json.dump(metrics, f, indent=2)
    return model, metrics


def load():
    global _model
    if _model is None:
        if os.path.exists(MODEL_PATH):
            try:
                _model = joblib.load(MODEL_PATH)
            except Exception:
                _model, _ = train()
        else:
            _model, _ = train()
    return _model


def metrics():
    load()
    if not os.path.exists(METRICS_PATH):
        train()
    with open(METRICS_PATH) as f:
        m = json.load(f)
    if "comparison" not in m:          # metrics from an older version -> retrain
        _, m = train()
    return m


# ---------------------------------------------------------------- inference
def features_from(records, detection):
    m = detection["metrics"]
    total = max(m["total_files"], 1)
    deltas = [r["entropy_after"] - r["entropy_before"] for r in records]
    high = sum(1 for r in records if r["content_changed"] and r["entropy_after"] >= 7.5)
    ext = [r for r in records if os.path.splitext(r["original"])[1] != os.path.splitext(r["final"])[1]]
    ransom = [r for r in ext if os.path.splitext(r["final"])[1].lower()
              in {".locked", ".enc", ".crypt", ".encrypted", ".crypted"}]
    return {
        "rename_rate": m["rename_rate"],
        "entropy_after": m["entropy_after"],
        "entropy_delta": round(sum(deltas) / len(deltas), 3) if deltas else 0.0,
        "high_entropy_ratio": round(high / total, 3),
        "log_speed": round(math.log10(1 + m["speed"]), 3),
        "ext_change_ratio": round(len(ext) / total, 3),
        "ransom_ext_ratio": round(len(ransom) / total, 3),
    }


def predict(feature_dict):
    model = load()
    x = np.array([[feature_dict[f] for f in FEATURES]])
    proba = float(model.predict_proba(x)[0][1])
    return {
        "probability": round(proba, 4),
        "label": "ransomware" if proba >= 0.5 else "benign",
        "features": feature_dict,
    }


if __name__ == "__main__":
    _, m = train()
    print("Model comparison:")
    for c in m["comparison"]:
        print(f"  {c['model']:<20} acc {c['accuracy']*100:.1f}%  prec {c['precision']*100:.1f}%  "
              f"rec {c['recall']*100:.1f}%  F1 {c['f1']*100:.1f}%  train {c['train_ms']} ms")
    print(f"Accuracy: {m['accuracy']*100:.2f}%")
    print("Confusion matrix [[TN, FP], [FN, TP]]:", m["confusion_matrix"])
    print("Feature importance:", m["feature_importance"])
    print(m["rules"])
