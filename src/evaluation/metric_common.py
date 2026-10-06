import time

import numpy as np

from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


# ============================================================
# INPUT CHECK
# ============================================================

def validate_binary_inputs(y_true, y_score):
    """
    y_true:
        0 = benign
        1 = malicious

    y_score:
        malicious score/probability.
        Higher = more likely malicious.
    """

    y_true = np.asarray(y_true)
    y_score = np.asarray(y_score, dtype=float)

    if y_true.ndim != 1:
        raise ValueError("y_true must be 1D.")

    if y_score.ndim != 1:
        raise ValueError("y_score must be 1D.")

    if len(y_true) != len(y_score):
        raise ValueError(
            "y_true and y_score must have the same length."
        )

    labels = set(np.unique(y_true))

    if not labels.issubset({0, 1}):
        raise ValueError(
            "y_true must contain only 0 and 1."
        )

    if len(labels) < 2:
        raise ValueError(
            "y_true must contain both classes."
        )

    if np.isnan(y_score).any():
        raise ValueError(
            "y_score contains NaN."
        )

    return (
        y_true.astype(int),
        y_score
    )


# ============================================================
# THRESHOLD
# ============================================================

def select_threshold_at_fpr(
    y_true,
    y_score,
    target_fpr=0.01
):
    """
    Chỉ dùng hàm này trên VALIDATION A.

    Chọn threshold có recall cao nhất
    với FPR <= target_fpr.
    """

    y_true, y_score = validate_binary_inputs(
        y_true,
        y_score
    )

    fpr, tpr, thresholds = roc_curve(
        y_true,
        y_score
    )

    valid = np.where(
        fpr <= target_fpr
    )[0]

    if len(valid) == 0:
        raise RuntimeError(
            "No threshold satisfies target FPR."
        )

    best_idx = valid[
        np.argmax(tpr[valid])
    ]

    threshold = float(
        thresholds[best_idx]
    )

    info = {
        "threshold":
            threshold,

        "target_fpr":
            float(target_fpr),

        "validation_fpr":
            float(fpr[best_idx]),

        "validation_recall":
            float(tpr[best_idx]),
    }

    return threshold, info


# ============================================================
# FIXED-THRESHOLD METRICS
# ============================================================

def evaluate_at_threshold(
    y_true,
    y_score,
    threshold
):
    """
    Dùng cùng threshold đã lấy từ validation A
    cho test_A, test_B, test_C và attack.
    """

    y_true, y_score = validate_binary_inputs(
        y_true,
        y_score
    )

    y_pred = (
        y_score >= threshold
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    ).ravel()

    fpr = (
        fp / (fp + tn)
        if fp + tn > 0
        else 0.0
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0
    )

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0
    )

    return {
        "threshold":
            float(threshold),

        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),

        "fpr":
            float(fpr),

        "precision":
            float(precision),

        "recall":
            float(recall),

        "f1":
            float(f1),
    }


# ============================================================
# SCORE METRICS
# ============================================================

def evaluate_scores(
    y_true,
    y_score,
    threshold
):
    """
    Metric chung cho E1/E2/E3/E4.
    """

    y_true, y_score = validate_binary_inputs(
        y_true,
        y_score
    )

    result = evaluate_at_threshold(
        y_true,
        y_score,
        threshold
    )

    result["roc_auc"] = float(
        roc_auc_score(
            y_true,
            y_score
        )
    )

    result["pr_auc"] = float(
        average_precision_score(
            y_true,
            y_score
        )
    )

    return result


# ============================================================
# ATTACK SUCCESS RATE
# ============================================================

def attack_success_rate(
    clean_scores,
    adversarial_scores,
    threshold
):
    """
    ASR:
    Trong các URL malicious ban đầu model bắt đúng,
    bao nhiêu % trở thành benign sau attack.
    """

    clean_scores = np.asarray(
        clean_scores,
        dtype=float
    )

    adversarial_scores = np.asarray(
        adversarial_scores,
        dtype=float
    )

    if len(clean_scores) != len(
        adversarial_scores
    ):
        raise ValueError(
            "Clean and adversarial scores "
            "must have same length."
        )

    initially_detected = (
        clean_scores >= threshold
    )

    n_detected = int(
        initially_detected.sum()
    )

    if n_detected == 0:
        return {
            "initially_detected": 0,
            "evaded": 0,
            "attack_success_rate": 0.0,
        }

    evaded = (
        initially_detected
        &
        (
            adversarial_scores
            < threshold
        )
    )

    n_evaded = int(
        evaded.sum()
    )

    return {
        "initially_detected":
            n_detected,

        "evaded":
            n_evaded,

        "attack_success_rate":
            float(
                n_evaded / n_detected
            ),
    }


# ============================================================
# DOMAIN SHIFT GAP
# ============================================================

def source_gap(
    metric_a,
    metric_other
):
    """
    Ví dụ:
        gap A -> B = F1_A - F1_B
    """

    return float(
        metric_a - metric_other
    )


# ============================================================
# PREDICTION TIME
# ============================================================

def measure_prediction_time(
    predict_fn,
    X,
    repeats=5
):
    """
    Đo thời gian dự đoán trung bình cho 1 URL.
    """

    if len(X) == 0:
        raise ValueError(
            "X cannot be empty."
        )

    # warm-up
    predict_fn(X)

    times = []

    for _ in range(repeats):

        start = time.perf_counter()

        predict_fn(X)

        end = time.perf_counter()

        times.append(
            end - start
        )

    avg_total = float(
        np.mean(times)
    )

    per_url = (
        avg_total / len(X)
    )

    return {
        "n_urls":
            int(len(X)),

        "avg_total_seconds":
            avg_total,

        "avg_ms_per_url":
            float(
                per_url * 1000
            ),
    }


# ============================================================
# SELF TEST
# ============================================================

if __name__ == "__main__":

    print(
        "=== METRIC COMMON SELF TEST ==="
    )

    rng = np.random.default_rng(
        42
    )

    # ----------------------------------------
    # Random classifier
    # ----------------------------------------

    n = 100000

    y_true = rng.integers(
        0,
        2,
        size=n
    )

    y_score = rng.random(
        n
    )

    threshold, threshold_info = (
        select_threshold_at_fpr(
            y_true,
            y_score,
            target_fpr=0.01
        )
    )

    result = evaluate_scores(
        y_true,
        y_score,
        threshold
    )

    print(
        "\nThreshold selection:"
    )

    print(
        threshold_info
    )

    print(
        "\nMetrics:"
    )

    for key, value in result.items():

        print(
            f"{key}: {value}"
        )


    # ----------------------------------------
    # Sanity checks
    # ----------------------------------------

    assert (
        0.45
        <= result["roc_auc"]
        <= 0.55
    )

    assert (
        0.45
        <= result["pr_auc"]
        <= 0.55
    )

    assert (
        result["fpr"]
        <= 0.011
    )


    # ----------------------------------------
    # ASR sanity test
    # ----------------------------------------

    clean = np.array([
        0.9,
        0.8,
        0.7,
        0.4
    ])

    adversarial = np.array([
        0.2,
        0.3,
        0.8,
        0.2
    ])

    asr = attack_success_rate(
        clean,
        adversarial,
        threshold=0.5
    )

    print(
        "\nAttack success test:"
    )

    print(
        asr
    )

    assert (
        asr["initially_detected"]
        == 3
    )

    assert (
        asr["evaded"]
        == 2
    )

    print(
        "\nSELF TEST PASSED"
    )
    