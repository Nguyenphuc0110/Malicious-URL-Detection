"""Experimental LR-F2 with leading www removed from hostname features."""

from pathlib import Path

import pandas as pd
from sklearn.linear_model import LogisticRegression

from src.features.f2_no_www import F2VectorizerNoWWW
from src.models.detector import URLDetector
from src.models.train_baselines import load_split
from src.models.quick_metrics import evaluate, pick_threshold_at_fpr


DATA = Path("data/processed/handoff")
MODEL = Path("models/lr_f2_no_www.joblib")
REPORT = Path("reports/lr_f2_no_www_metrics.csv")


def main():
    if MODEL.exists() or REPORT.exists():
        raise SystemExit(
            "V4 output already exists. Refusing to overwrite."
        )

    print("=== LR-F2 NO-WWW EXPERIMENT ===", flush=True)

    train = load_split(str(DATA / "train.csv"))
    val = load_split(str(DATA / "val.csv"))
    source_b = load_split(str(DATA / "test_B.csv"))

    print("Training rows:", len(train), flush=True)
    print("Validation rows:", len(val), flush=True)
    print("Source B rows:", len(source_b), flush=True)

    print("Fitting new F2 vocabulary on TRAIN only...", flush=True)

    vectorizer = F2VectorizerNoWWW()
    vectorizer.fit(train["url"].tolist())

    print("Vocabulary size:", vectorizer.n_features, flush=True)

    X_train = vectorizer.transform(train["url"].tolist())
    y_train = train["label"].to_numpy()

    model = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        solver="liblinear",
        random_state=42,
    )

    print("Training LR-F2-NoWWW...", flush=True)
    model.fit(X_train, y_train)

    detector = URLDetector(
        name="lr_f2_no_www",
        feature_kind="f2",
        model=model,
        f2_vectorizer=vectorizer,
    )

    print("Selecting validation threshold...", flush=True)

    val_scores = detector.score(val["url"].tolist())

    detector.threshold = float(
        pick_threshold_at_fpr(
            val["label"].to_numpy(),
            val_scores,
            0.01,
        )
    )

    print("Threshold:", detector.threshold, flush=True)

    results = []

    for name, df in [
        ("val_A", val),
        ("source_B_exploratory", source_b),
    ]:
        scores = detector.score(df["url"].tolist())

        metrics = evaluate(
            df["label"].to_numpy(),
            scores,
            detector.threshold,
        )

        metrics.update(
            model="lr_f2_no_www",
            dataset=name,
            n=len(df),
        )

        results.append(metrics)

    report = pd.DataFrame(results)

    print("\n=== NO-WWW MODEL EVALUATION ===")
    columns = [
        "model", "dataset", "n",
        "precision", "recall", "f1",
        "fpr", "pr_auc",
    ]
    print(report[columns].round(4).to_string(index=False))

    print("\n=== FAMOUS URL CHECK ===")

    for url in [
        "https://github.com",
        "https://www.youtube.com",
        "https://www.google.com",
        "https://www.wikipedia.org",
        "https://example.com/login",
    ]:
        score = float(detector.score([url])[0])
        status = (
            "ALERT"
            if score >= detector.threshold
            else "NO ALERT"
        )

        print(f"{score:.6f} | {status:8} | {url}")

    MODEL.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    detector.save(str(MODEL))
    report.to_csv(REPORT, index=False)

    print("\nMODEL SAVED:", MODEL)
    print("REPORT SAVED:", REPORT)
    print("LR-F2 NO-WWW TRAINING COMPLETE")


if __name__ == "__main__":
    main()
