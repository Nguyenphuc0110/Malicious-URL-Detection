"""Metric TẠM THỜI để Dũng train/đánh giá baseline khi Hiếu chưa xong D1.

⚠ Khi Hiếu hoàn thành src/eval/metric_common.py (Task D1), MỌI số liệu đưa vào
báo cáo phải chạy lại bằng metric_common — file này chỉ để dev nhanh.
Nguyên tắc chung không đổi: ngưỡng chọn trên VALIDATION nguồn A sao cho FPR≈1%,
rồi GIỮ NGUYÊN khi test ở mọi nơi khác.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score, roc_curve)


def pick_threshold_at_fpr(y_true, scores, target_fpr: float = 0.01) -> float:
    """Ngưỡng lớn nhất-recall sao cho FPR <= target_fpr (dự đoán dương khi score >= thr)."""
    fpr, tpr, thr = roc_curve(y_true, scores)
    ok = np.where(fpr <= target_fpr)[0]
    idx = ok[-1] if len(ok) else 0
    t = thr[idx]
    if not np.isfinite(t):                       # roc_curve trả +inf ở điểm đầu
        t = np.nextafter(np.max(scores), np.inf)
    return float(t)


def evaluate(y_true, scores, threshold: float) -> dict:
    y_true = np.asarray(y_true)
    pred = (np.asarray(scores) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "precision": precision_score(y_true, pred, zero_division=0),
        "recall": recall_score(y_true, pred, zero_division=0),   # = Recall@FPR cố định khi thr chọn ở val
        "f1": f1_score(y_true, pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "pr_auc": average_precision_score(y_true, scores),
        "roc_auc": roc_auc_score(y_true, scores) if len(np.unique(y_true)) > 1 else float("nan"),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }
