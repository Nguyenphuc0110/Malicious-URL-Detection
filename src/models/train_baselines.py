"""Task B4 — Train baseline & model mạnh hơn (owner: Dũng).

Chạy:
    python -m src.models.train_baselines --data-dir data/processed --out-dir models \
        --report-dir reports [--source-b data/processed/test_B.csv] [--seed 42]

Đầu vào (Phúc bàn giao ở A5): train.csv, val.csv, test_A.csv, cột: url, label (0=benign, 1=malicious)
  (nếu có cột `orig_class`, các dòng defacement/spam sẽ bị loại khỏi bài toán chính).

Đầu ra:
  models/*.joblib               5 URLDetector đã đặt threshold  (Nam/Hiếu dùng lại, KHÔNG train lại)
  models/f2_vectorizer.joblib   vectorizer F2 đã fit trên train (Phúc dùng ở A6)
  reports/baseline_results.csv  Recall@FPR1%, F1, PR-AUC... trên val/test_A/(B)
  reports/imbalance_note.txt    tỉ lệ lớp gốc + cách xử lý  (BẮT BUỘC theo rubric)
  reports/hyperparameters.json  hyperparameter đã dùng (cần cho phần rationale)
"""
from __future__ import annotations

import argparse
import json
import os
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier

from src.features.f1_lexical import build_f1_matrix
from src.features.f2_ngram import F2Vectorizer
from src.models.detector import URLDetector
from src.models.quick_metrics import evaluate, pick_threshold_at_fpr

EXCLUDED_CLASSES = {"defacement", "spam"}   # chỉ dùng ở E1, không thuộc bài toán chính


def load_split(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    if not {"url", "label"} <= set(df.columns):
        raise ValueError(f"{path} phải có cột url, label")
    if "orig_class" in df.columns:
        df = df[~df["orig_class"].astype(str).str.lower().isin(EXCLUDED_CLASSES)]
    df = df.dropna(subset=["url", "label"]).copy()
    df["label"] = df["label"].astype(int)
    return df.reset_index(drop=True)


def imbalance_report(y: np.ndarray, report_dir: str) -> float:
    """Bước 0: kiểm tra mất cân bằng lớp và ghi lại (bắt buộc theo rubric)."""
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())
    ratio = n_neg / max(n_pos, 1)
    minority = min(n_pos, n_neg) / (n_pos + n_neg)
    imbalanced = minority < 0.35
    msg = (
        f"Train: benign={n_neg}, malicious={n_pos}, tỉ lệ benign/malicious={ratio:.2f}, "
        f"lớp thiểu số chiếm {minority:.1%}.\n"
        + ("Dữ liệu LỆCH -> dùng class_weight='balanced' (LR/RF/SVM) và scale_pos_weight (XGBoost); "
           "KHÔNG resample để giữ nguyên phân phối val/test. Ngưỡng chọn theo FPR=1% nên "
           "không phụ thuộc accuracy.\n" if imbalanced else
           "Dữ liệu tương đối cân bằng -> vẫn dùng class_weight='balanced' cho an toàn.\n")
    )
    os.makedirs(report_dir, exist_ok=True)
    with open(os.path.join(report_dir, "imbalance_note.txt"), "w", encoding="utf-8") as f:
        f.write(msg)
    print(msg)
    return ratio


def make_models(seed: int, scale_pos_weight: float) -> dict:
    """(tên, feature_kind, model). Hyperparameter ghi ra JSON để đưa vào báo cáo."""
    return {
        "lr_f1": ("f1", make_pipeline(StandardScaler(),
                  LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed))),
        "rf_f1": ("f1", RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample",
                                                n_jobs=-1, random_state=seed)),
        "xgb_f1": ("f1", XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                                        scale_pos_weight=scale_pos_weight, eval_metric="logloss",
                                        tree_method="hist", n_jobs=-1, random_state=seed)),
        "lr_f2": ("f2", LogisticRegression(max_iter=2000, class_weight="balanced",
                                            solver="liblinear", random_state=seed)),
        "svm_f2": ("f2", LinearSVC(class_weight="balanced", C=1.0, random_state=seed)),
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/processed")
    ap.add_argument("--out-dir", default="models")
    ap.add_argument("--report-dir", default="reports")
    ap.add_argument("--source-b", default=None, help="CSV nguồn B đã chuẩn hóa (url,label) để test khác nguồn")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    os.makedirs(args.out_dir, exist_ok=True)
    os.makedirs(args.report_dir, exist_ok=True)

    train = load_split(os.path.join(args.data_dir, "train.csv"))
    val = load_split(os.path.join(args.data_dir, "val.csv"))
    test_a = load_split(os.path.join(args.data_dir, "test_A.csv"))
    evalsets = {"val_A": val, "test_A": test_a}
    if args.source_b:
        evalsets["source_B"] = load_split(args.source_b)

    ratio = imbalance_report(train["label"].values, args.report_dir)

    # --- features: fit F2 CHỈ trên train ---
    print("Trích feature...")
    f2 = F2Vectorizer().fit(train["url"])
    f2.save(os.path.join(args.out_dir, "f2_vectorizer.joblib"))
    print(f"F2 vocab (host, path): {f2.n_features}")
    Xtr = {"f1": build_f1_matrix(train["url"]), "f2": f2.transform(train["url"])}
    ytr = train["label"].values

    hyper, rows = {}, []
    for name, (kind, model) in make_models(args.seed, ratio).items():
        t0 = time.time()
        model.fit(Xtr[kind], ytr)
        det = URLDetector(name, kind, model, f2_vectorizer=f2 if kind == "f2" else None)

        # ngưỡng: chọn 1 lần trên val_A (FPR≈1%), rồi giữ nguyên ở mọi nơi
        val_scores = det.score(val["url"])
        det.threshold = pick_threshold_at_fpr(val["label"].values, val_scores, 0.01)
        det.save(os.path.join(args.out_dir, f"{name}.joblib"))
        hyper[name] = {"feature": kind, "threshold_fpr1pct": det.threshold, "seed": args.seed,
                       "params": {k: str(v) for k, v in model.get_params(deep=False).items()}}
        for setname, df in evalsets.items():
            s = det.score(df["url"]) if setname != "val_A" else val_scores
            r = evaluate(df["label"].values, s, det.threshold)
            r.update(model=name, feature=kind, dataset=setname, n=len(df))
            rows.append(r)
        print(f"  {name:8s} xong ({time.time()-t0:.1f}s)  thr={det.threshold:.4f}")

    res = pd.DataFrame(rows)
    cols = ["model", "feature", "dataset", "n", "recall", "precision", "f1", "fpr", "pr_auc", "roc_auc",
            "tp", "fp", "tn", "fn"]
    res = res[cols]
    res.to_csv(os.path.join(args.report_dir, "baseline_results.csv"), index=False)
    with open(os.path.join(args.report_dir, "hyperparameters.json"), "w", encoding="utf-8") as f:
        json.dump(hyper, f, ensure_ascii=False, indent=2)

    print("\n=== Kết quả (ngưỡng cố định từ val_A, FPR≈1%) ===")
    print(res[["model", "dataset", "recall", "precision", "f1", "fpr", "pr_auc"]]
          .round(4).to_string(index=False))

    suspicious = res[(res.dataset == "test_A") & (res.f1 > 0.995)]
    if len(suspicious):
        print("\n⚠ CẢNH BÁO: F1 test_A > 0.995 ở:", list(suspicious.model),
              "\n  -> kiểm tra rò rỉ domain ở Task A5 (Phúc) trước khi tin kết quả.")


if __name__ == "__main__":
    main()
