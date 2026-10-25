"""Train an experimental root-normalized XGBoost F1 model."""

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_curve,
)
from xgboost import XGBClassifier

from src.features.f1_lexical import build_f1_matrix
from src.features.url_root_normalization import ensure_root_slash
from src.models.detector import URLDetector


DATA_DIR = Path("data/processed/handoff")
MODEL_PATH = Path("models/xgb_f1_v2.joblib")
REPORT_PATH = Path("reports/xgb_f1_v2_metrics.csv")
SEED = 42


def load_split(filename):
    df = pd.read_csv(DATA_DIR / filename)

    if "orig_class" in df.columns:
        excluded = {"defacement", "spam"}
        df = df[
            ~df["orig_class"].astype(str).str.lower().isin(excluded)
        ]

    df = df.dropna(subset=["url", "label"]).copy()
    df["url"] = df["url"].astype(str)
    df["label"] = df["label"].astype(int)

    if not df["label"].isin([0, 1]).all():
        raise ValueError("Expected labels 0=benign, 1=malicious")

    return df.reset_index(drop=True)


def evaluate(detector, df, dataset):
    y = df["label"].to_numpy()
    scores = detector.score(df["url"].tolist())
    predicted = (scores >= detector.threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y, predicted, labels=[0, 1]
    ).ravel()

    return {
        "model": "xgb_f1_v2",
        "dataset": dataset,
        "n": len(df),
        "precision": precision_score(
            y, predicted, zero_division=0
        ),
        "recall": recall_score(
            y, predicted, zero_division=0
        ),
        "f1": f1_score(
            y, predicted, zero_division=0
        ),
        "fpr": fp / (fp + tn) if fp + tn else 0,
        "pr_auc": average_precision_score(y, scores),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }


def main():
    for target in (MODEL_PATH, REPORT_PATH):
        if target.exists():
            raise SystemExit(
                f"Refusing to overwrite existing file: {target}"
            )

    print("=== TRAIN XGB-F1-V2 ===", flush=True)

    train = load_split("train.csv")
    val = load_split("val.csv")
    test = load_split("test_A.csv")

    print("Train rows:", len(train), flush=True)
    print("Validation rows:", len(val), flush=True)
    print("Test A rows:", len(test), flush=True)

    normalized_urls = train["url"].map(ensure_root_slash)

    print(
        "Normalized training URLs:",
        int((normalized_urls != train["url"]).sum()),
        flush=True,
    )

    x_train = build_f1_matrix(normalized_urls)
    y_train = train["label"].to_numpy()

    n_positive = int((y_train == 1).sum())
    n_negative = int((y_train == 0).sum())
    class_ratio = n_negative / max(n_positive, 1)

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=class_ratio,
        eval_metric="logloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=SEED,
    )

    print("Training XGBoost V2...", flush=True)
    model.fit(x_train, y_train)

    detector = URLDetector(
        name="xgb_f1_v2",
        feature_kind="f1",
        model=model,
        preprocess=ensure_root_slash,
    )

    print("Selecting threshold on validation...", flush=True)

    val_scores = detector.score(val["url"].tolist())

    if not np.isfinite(val_scores).all():
        raise ValueError("Non-finite validation scores")

    fpr, tpr, thresholds = roc_curve(
        val["label"].to_numpy(),
        val_scores,
    )

    allowed = np.flatnonzero(
        (fpr <= 0.01) & np.isfinite(thresholds)
    )

    if len(allowed) == 0:
        raise ValueError("Cannot select a finite threshold")

    chosen = allowed[np.argmax(tpr[allowed])]
    detector.threshold = float(thresholds[chosen])

    print("Threshold:", detector.threshold, flush=True)

    results = pd.DataFrame([
        evaluate(detector, val, "val_A"),
        evaluate(detector, test, "test_A_exploratory"),
    ])

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    detector.save(str(MODEL_PATH))

    # Confirm normalization survives serialization.
    loaded = URLDetector.load(str(MODEL_PATH))
    assert loaded.preprocess("https://github.com") == (
        "https://github.com/"
    )

    results.to_csv(REPORT_PATH, index=False)

    print("\n=== V2 EVALUATION ===")
    columns = [
        "dataset", "precision", "recall",
        "f1", "fpr", "pr_auc", "fn", "fp",
    ]
    print(results[columns].round(4).to_string(index=False))

    print("\nMODEL SAVED:", MODEL_PATH)
    print("REPORT SAVED:", REPORT_PATH)
    print("V2 TRAINING COMPLETE")


if __name__ == "__main__":
    main()
