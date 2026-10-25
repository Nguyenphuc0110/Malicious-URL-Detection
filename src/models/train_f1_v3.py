"""Experimental XGB-F1-V3 with weighted root-path augmentation."""

from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    roc_curve,
)
from xgboost import XGBClassifier

from src.features.f1_lexical import build_f1_matrix
from src.models.detector import URLDetector


DATA = Path("data/processed/handoff")
MODEL = Path("models/xgb_f1_v3.joblib")
REPORT = Path("reports/xgb_f1_v3_metrics.csv")


def load_data(filename):
    df = pd.read_csv(DATA / filename)

    if "orig_class" in df.columns:
        excluded = {"defacement", "spam"}
        df = df[
            ~df["orig_class"].astype(str).str.lower().isin(excluded)
        ]

    df = df.dropna(subset=["url", "label"]).copy()
    df["url"] = df["url"].astype(str)
    df["label"] = df["label"].astype(int)

    if not df["label"].isin([0, 1]).all():
        raise ValueError("Invalid binary labels")

    return df.reset_index(drop=True)


def mirror_root(url):
    """Create the equivalent root URL with opposite slash form."""
    try:
        p = urlsplit(url)

        if p.scheme.lower() not in ("http", "https"):
            return None

        if not p.netloc or p.path not in ("", "/"):
            return None

        other_path = "/" if p.path == "" else ""
        result = urlunsplit(p._replace(path=other_path))

        return result if result != url else None

    except ValueError:
        return None


def augment_training(train):
    mirrored = train["url"].map(mirror_root)
    mask = mirrored.notna()

    extra = pd.DataFrame({
        "url": mirrored[mask].tolist(),
        "label": train.loc[mask, "label"].tolist(),
    })

    augmented = pd.concat(
        [train[["url", "label"]], extra],
        ignore_index=True,
    )

    original_weights = np.where(
        mask.to_numpy(), 0.5, 1.0
    ).astype(np.float32)

    extra_weights = np.full(
        len(extra), 0.5, dtype=np.float32
    )

    weights = np.concatenate([
        original_weights, extra_weights
    ])

    assert len(augmented) == len(weights)
    assert np.isclose(weights.sum(), len(train))

    return augmented, weights, len(extra)


def evaluate(det, df):
    y = df["label"].to_numpy()
    scores = det.score(df["url"].tolist())
    pred = (scores >= det.threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y, pred, labels=[0, 1]
    ).ravel()

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )

    return {
        "model": "xgb_f1_v3",
        "dataset": "val_A",
        "n": len(df),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "pr_auc": average_precision_score(y, scores),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }


def main():
    for path in (MODEL, REPORT):
        if path.exists():
            raise SystemExit(
                f"Refusing to overwrite existing file: {path}"
            )

    print("=== XGB-F1-V3 EXPERIMENT ===", flush=True)

    train = load_data("train.csv")
    val = load_data("val.csv")

    augmented, weights, added = augment_training(train)

    print("Original training rows:", len(train), flush=True)
    print("Augmented rows added:", added, flush=True)
    print("Total training rows:", len(augmented), flush=True)
    print("Total sample weight:", weights.sum(), flush=True)

    y = augmented["label"].to_numpy()

    original_positive = int(train["label"].eq(1).sum())
    original_negative = int(train["label"].eq(0).sum())

    ratio = original_negative / max(original_positive, 1)

    print("Extracting F1 features...", flush=True)
    X = build_f1_matrix(augmented["url"])

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=ratio,
        eval_metric="logloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=42,
    )

    print("Training V3...", flush=True)
    model.fit(X, y, sample_weight=weights)

    detector = URLDetector(
        name="xgb_f1_v3",
        feature_kind="f1",
        model=model,
    )

    print("Selecting validation threshold...", flush=True)

    val_scores = detector.score(val["url"].tolist())

    fpr, tpr, thresholds = roc_curve(
        val["label"].to_numpy(),
        val_scores,
    )

    valid = np.flatnonzero(
        (fpr <= 0.01) & np.isfinite(thresholds)
    )

    if len(valid) == 0:
        raise ValueError("Cannot choose a valid threshold")

    chosen = valid[np.argmax(tpr[valid])]
    detector.threshold = float(thresholds[chosen])

    result = pd.DataFrame([evaluate(detector, val)])

    MODEL.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    detector.save(str(MODEL))
    result.to_csv(REPORT, index=False)

    print("\n=== V3 VALIDATION ===")
    columns = [
        "dataset", "precision", "recall",
        "f1", "fpr", "pr_auc", "fn", "fp",
    ]
    print(result[columns].round(4).to_string(index=False))

    print("\n=== ROOT SLASH STABILITY ===")
    for url in [
        "https://github.com",
        "https://www.youtube.com",
    ]:
        a, b = detector.score([url, url + "/"])
        print(f"{url}: {a:.6f} vs {b:.6f}")

    print("\nMODEL SAVED:", MODEL)
    print("REPORT SAVED:", REPORT)
    print("V3 TRAIN SCRIPT COMPLETE")


if __name__ == "__main__":
    main()
