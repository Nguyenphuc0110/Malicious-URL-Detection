from pathlib import Path
import random

import pandas as pd

from src.attack.random_attack import (
    random_attack,
)


# ============================================================
# CONFIG
# ============================================================

RANDOM_SEED = 42
SAMPLE_SIZE = 1000

K_VALUES = [
    0,
    1,
    2,
    3,
    5,
]

TRAIN_PATH = Path(
    "data/processed/handoff/train.csv"
)

VAL_PATH = Path(
    "data/processed/handoff/val.csv"
)

TEST_A_PATH = Path(
    "data/processed/handoff/test_A.csv"
)

OUTPUT_SUMMARY = Path(
    "outputs/logs/random_attack_real_data_summary.csv"
)

OUTPUT_FAILURES = Path(
    "outputs/logs/random_attack_real_data_failures.csv"
)


# ============================================================
# LOAD BENIGN DOMAINS
# ============================================================

def load_benign_domains():
    """
    Chỉ dùng benign registered domains từ train + val.

    Không dùng benign labels của test_A.
    """

    print(
        "\n=== LOAD BENIGN DOMAIN SET ==="
    )

    benign_domains = set()

    for path in [
        TRAIN_PATH,
        VAL_PATH,
    ]:

        if not path.exists():
            raise FileNotFoundError(
                path
            )

        df = pd.read_csv(
            path,
            usecols=[
                "label",
                "registered_domain",
            ],
            low_memory=False,
        )

        benign = df[
            df["label"] == 0
        ].copy()

        domains = (
            benign[
                "registered_domain"
            ]
            .dropna()
            .astype(str)
            .str.lower()
            .str.strip()
        )

        benign_domains.update(
            domains
        )

        print(
            f"{path.name}: "
            f"{len(benign):,} benign rows"
        )

    print(
        "Unique benign domains:",
        f"{len(benign_domains):,}"
    )

    return benign_domains


# ============================================================
# LOAD MALICIOUS SAMPLE
# ============================================================

def load_malicious_sample():

    print(
        "\n=== LOAD MALICIOUS TEST_A ==="
    )

    if not TEST_A_PATH.exists():
        raise FileNotFoundError(
            TEST_A_PATH
        )

    df = pd.read_csv(
        TEST_A_PATH,
        low_memory=False,
    )

    required = {
        "url",
        "label",
    }

    missing = (
        required
        - set(df.columns)
    )

    if missing:
        raise ValueError(
            f"Missing columns: {missing}"
        )

    malicious = df[
        df["label"] == 1
    ].copy()

    malicious = malicious[
        malicious["url"].notna()
    ].copy()

    malicious[
        "url"
    ] = (
        malicious["url"]
        .astype(str)
        .str.strip()
    )

    malicious = malicious[
        malicious["url"] != ""
    ].copy()

    print(
        "Total malicious test_A:",
        f"{len(malicious):,}"
    )

    sample_n = min(
        SAMPLE_SIZE,
        len(malicious),
    )

    sample = malicious.sample(
        n=sample_n,
        random_state=RANDOM_SEED,
    ).reset_index(
        drop=True
    )

    print(
        "Sample size:",
        f"{len(sample):,}"
    )

    return sample


# ============================================================
# AUDIT ONE K
# ============================================================

def audit_k(
    sample,
    benign_domains,
    k,
):
    """
    Chạy random_attack trên toàn sample với budget k.
    """

    print(
        f"\n=== RANDOM ATTACK k={k} ==="
    )

    total = len(
        sample
    )

    changed_count = 0
    full_budget_count = 0
    error_count = 0
    duplicate_transform_count = 0
    over_budget_count = 0
    too_long_count = 0

    total_applied = 0

    failures = []

    for idx, row in sample.iterrows():

        original_url = str(
            row["url"]
        )

        try:

            adv_url, applied = random_attack(
                url=original_url,
                k=k,
                benign_domains_set=benign_domains,
            )

        except Exception as exc:

            error_count += 1

            failures.append(
                {
                    "k": k,
                    "row_index": idx,
                    "reason": "exception",
                    "original_url": original_url,
                    "adv_url": "",
                    "applied": "",
                    "details": repr(exc),
                }
            )

            continue

        # ----------------------------------------------------
        # APPLIED COUNT
        # ----------------------------------------------------

        applied_count = len(
            applied
        )

        total_applied += (
            applied_count
        )

        if applied_count == k:
            full_budget_count += 1

        # ----------------------------------------------------
        # CHANGED
        # ----------------------------------------------------

        if adv_url != original_url:
            changed_count += 1

        # ----------------------------------------------------
        # NO DUPLICATE TRANSFORM
        # ----------------------------------------------------

        if (
            len(applied)
            != len(set(applied))
        ):

            duplicate_transform_count += 1

            failures.append(
                {
                    "k": k,
                    "row_index": idx,
                    "reason": (
                        "duplicate_transform"
                    ),
                    "original_url": original_url,
                    "adv_url": adv_url,
                    "applied": "|".join(
                        applied
                    ),
                    "details": "",
                }
            )

        # ----------------------------------------------------
        # BUDGET
        # ----------------------------------------------------

        if applied_count > k:

            over_budget_count += 1

            failures.append(
                {
                    "k": k,
                    "row_index": idx,
                    "reason": "over_budget",
                    "original_url": original_url,
                    "adv_url": adv_url,
                    "applied": "|".join(
                        applied
                    ),
                    "details": (
                        f"applied={applied_count}"
                    ),
                }
            )

        # ----------------------------------------------------
        # LENGTH
        # ----------------------------------------------------

        if len(adv_url) > 2048:

            too_long_count += 1

            failures.append(
                {
                    "k": k,
                    "row_index": idx,
                    "reason": "url_too_long",
                    "original_url": original_url,
                    "adv_url": adv_url,
                    "applied": "|".join(
                        applied
                    ),
                    "details": (
                        f"length={len(adv_url)}"
                    ),
                }
            )

        # ----------------------------------------------------
        # k=0 MUST NOT CHANGE URL
        # ----------------------------------------------------

        if k == 0:

            if (
                adv_url != original_url
                or applied
            ):

                failures.append(
                    {
                        "k": k,
                        "row_index": idx,
                        "reason": (
                            "k0_changed_url"
                        ),
                        "original_url": original_url,
                        "adv_url": adv_url,
                        "applied": "|".join(
                            applied
                        ),
                        "details": "",
                    }
                )

    changed_rate = (
        changed_count
        / total
        * 100
    )

    full_budget_rate = (
        full_budget_count
        / total
        * 100
    )

    average_applied = (
        total_applied
        / total
    )

    print(
        "Total:",
        total
    )

    print(
        "Changed:",
        changed_count,
        f"({changed_rate:.2f}%)"
    )

    print(
        "Full budget:",
        full_budget_count,
        f"({full_budget_rate:.2f}%)"
    )

    print(
        "Average transforms applied:",
        f"{average_applied:.3f}"
    )

    print(
        "Errors:",
        error_count
    )

    print(
        "Duplicate transforms:",
        duplicate_transform_count
    )

    print(
        "Over budget:",
        over_budget_count
    )

    print(
        "URLs > 2048:",
        too_long_count
    )

    summary = {
        "k": k,
        "total": total,
        "changed": changed_count,
        "changed_rate_percent": round(
            changed_rate,
            2,
        ),
        "full_budget": full_budget_count,
        "full_budget_rate_percent": round(
            full_budget_rate,
            2,
        ),
        "average_applied": round(
            average_applied,
            3,
        ),
        "errors": error_count,
        "duplicate_transforms": (
            duplicate_transform_count
        ),
        "over_budget": over_budget_count,
        "too_long": too_long_count,
    }

    return (
        summary,
        failures,
    )


# ============================================================
# MAIN
# ============================================================

def main():

    random.seed(
        RANDOM_SEED
    )

    print(
        "========================================"
    )

    print(
        "REAL DATA RANDOM ATTACK AUDIT"
    )

    print(
        "========================================"
    )

    benign_domains = (
        load_benign_domains()
    )

    sample = (
        load_malicious_sample()
    )

    summaries = []

    all_failures = []

    # ========================================================
    # TEST ALL K VALUES
    # ========================================================

    for k in K_VALUES:

        summary, failures = audit_k(
            sample,
            benign_domains,
            k,
        )

        summaries.append(
            summary
        )

        all_failures.extend(
            failures
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    summary_df = pd.DataFrame(
        summaries
    )

    print(
        "\n========================================"
    )

    print(
        "SUMMARY"
    )

    print(
        "========================================"
    )

    print(
        summary_df.to_string(
            index=False
        )
    )

    # ========================================================
    # HARD CHECKS
    # ========================================================

    print(
        "\n========================================"
    )

    print(
        "HARD CHECKS"
    )

    print(
        "========================================"
    )

    total_errors = int(
        summary_df[
            "errors"
        ].sum()
    )

    total_duplicates = int(
        summary_df[
            "duplicate_transforms"
        ].sum()
    )

    total_over_budget = int(
        summary_df[
            "over_budget"
        ].sum()
    )

    total_too_long = int(
        summary_df[
            "too_long"
        ].sum()
    )

    print(
        "Total errors:",
        total_errors
    )

    print(
        "Duplicate transforms:",
        total_duplicates
    )

    print(
        "Over-budget attacks:",
        total_over_budget
    )

    print(
        "URLs > 2048:",
        total_too_long
    )

    assert (
        total_errors
        == 0
    )

    assert (
        total_duplicates
        == 0
    )

    assert (
        total_over_budget
        == 0
    )

    assert (
        total_too_long
        == 0
    )

    # k=0 phải hoàn toàn unchanged.
    zero_row = summary_df[
        summary_df[
            "k"
        ] == 0
    ].iloc[0]

    assert (
        int(
            zero_row[
                "changed"
            ]
        )
        == 0
    )

    assert (
        float(
            zero_row[
                "average_applied"
            ]
        )
        == 0.0
    )

    # ========================================================
    # SAVE
    # ========================================================

    OUTPUT_SUMMARY.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary_df.to_csv(
        OUTPUT_SUMMARY,
        index=False,
    )

    failures_df = pd.DataFrame(
        all_failures
    )

    if failures_df.empty:

        failures_df = pd.DataFrame(
            columns=[
                "k",
                "row_index",
                "reason",
                "original_url",
                "adv_url",
                "applied",
                "details",
            ]
        )

    failures_df.to_csv(
        OUTPUT_FAILURES,
        index=False,
    )

    print(
        "\nSaved summary:"
    )

    print(
        OUTPUT_SUMMARY
    )

    print(
        "Saved failures:"
    )

    print(
        OUTPUT_FAILURES
    )

    print(
        "\n========================================"
    )

    print(
        "REAL DATA RANDOM ATTACK AUDIT PASSED"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()