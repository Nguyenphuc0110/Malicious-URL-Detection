from pathlib import Path
import random

import pandas as pd

from src.attack.transforms import (
    TRANSFORM_FUNCTIONS,
    extract_registered_domain,
    validate_transform,
)


# ============================================================
# CONFIG
# ============================================================

RANDOM_SEED = 42
SAMPLE_SIZE = 1000

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
    "outputs/logs/attack_real_data_summary.csv"
)

OUTPUT_FAILURES = Path(
    "outputs/logs/attack_real_data_failures.csv"
)


# ============================================================
# LOAD BENIGN DOMAIN SET
# ============================================================

def load_benign_domains():
    """
    Tạo tập registered_domain lành tính từ train + val.

    Không dùng benign label của test_A để tránh test leakage.
    Chỉ lấy label == 0.
    """

    print(
        "\n=== LOAD BENIGN DOMAIN SET ==="
    )

    benign_domains = set()

    # CHỈ DÙNG TRAIN + VAL
    # KHÔNG DÙNG TEST_A
    paths = [
        TRAIN_PATH,
        VAL_PATH,
    ]

    for path in paths:

        if not path.exists():
            raise FileNotFoundError(
                f"Missing file: {path}"
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
# LOAD MALICIOUS SAMPLE FROM TEST A
# ============================================================

def load_malicious_sample():
    """
    Load malicious URLs thật từ test_A.csv.

    test_A chỉ được dùng làm tập URLs cần attack.
    Không dùng benign label của test_A để xây benign domain set.
    """

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

    required_columns = {
        "url",
        "label",
        "registered_domain",
    }

    missing_columns = (
        required_columns
        - set(df.columns)
    )

    if missing_columns:

        raise ValueError(
            "Missing columns in test_A.csv: "
            f"{missing_columns}"
        )

    # Chỉ lấy malicious
    malicious = df[
        df["label"] == 1
    ].copy()

    # Bỏ missing URL
    malicious = malicious[
        malicious["url"].notna()
    ].copy()

    # Chuẩn hóa string nhẹ
    malicious[
        "url"
    ] = (
        malicious["url"]
        .astype(str)
        .str.strip()
    )

    # Bỏ URL rỗng
    malicious = malicious[
        malicious["url"] != ""
    ].copy()

    print(
        "Total malicious test_A:",
        f"{len(malicious):,}"
    )

    if len(malicious) == 0:

        raise RuntimeError(
            "No malicious URLs found in test_A.csv."
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
# AUDIT ONE TRANSFORM
# ============================================================

def audit_transform(
    sample,
    code,
    transform_fn,
    benign_domains,
):
    """
    Chạy một transform trên toàn bộ malicious sample.

    Kiểm tra:

    1. Có crash hay không.
    2. URL có thực sự thay đổi hay không.
    3. validate_transform() có chấp nhận hay không.
    4. URL có vượt 2048 ký tự hay không.
    5. T1-T4 có giữ nguyên registered domain hay không.
    """

    print(
        f"\n=== AUDIT {code} ==="
    )

    total = len(
        sample
    )

    changed_count = 0
    valid_count = 0
    noop_count = 0
    error_count = 0
    too_long_count = 0
    domain_violation_count = 0

    failures = []

    # ========================================================
    # LOOP THROUGH URL SAMPLE
    # ========================================================

    for idx, row in sample.iterrows():

        original_url = str(
            row["url"]
        )

        original_domain = (
            extract_registered_domain(
                original_url
            )
        )

        # ----------------------------------------------------
        # APPLY TRANSFORM
        # ----------------------------------------------------

        try:

            transformed_url = (
                transform_fn(
                    original_url
                )
            )

        except Exception as exc:

            error_count += 1

            failures.append(
                {
                    "transform": code,
                    "row_index": idx,
                    "reason": "exception",
                    "original_url": original_url,
                    "transformed_url": "",
                    "details": repr(exc),
                }
            )

            continue

        # ----------------------------------------------------
        # NO-OP CHECK
        # ----------------------------------------------------

        if (
            transformed_url
            == original_url
        ):

            noop_count += 1

            failures.append(
                {
                    "transform": code,
                    "row_index": idx,
                    "reason": "no_op",
                    "original_url": original_url,
                    "transformed_url": transformed_url,
                    "details": "",
                }
            )

        else:

            changed_count += 1

        # ----------------------------------------------------
        # LENGTH CHECK
        # ----------------------------------------------------

        if (
            len(transformed_url)
            > 2048
        ):

            too_long_count += 1

            failures.append(
                {
                    "transform": code,
                    "row_index": idx,
                    "reason": "url_too_long",
                    "original_url": original_url,
                    "transformed_url": transformed_url,
                    "details": (
                        f"length="
                        f"{len(transformed_url)}"
                    ),
                }
            )

        # ----------------------------------------------------
        # T1-T4 MUST PRESERVE REGISTERED DOMAIN
        # ----------------------------------------------------

        if code in {
            "T1",
            "T2",
            "T3",
            "T4",
        }:

            transformed_domain = (
                extract_registered_domain(
                    transformed_url
                )
            )

            if (
                transformed_url
                != original_url
                and transformed_domain
                != original_domain
            ):

                domain_violation_count += 1

                failures.append(
                    {
                        "transform": code,
                        "row_index": idx,
                        "reason": (
                            "registered_domain_changed"
                        ),
                        "original_url": original_url,
                        "transformed_url": transformed_url,
                        "details": (
                            f"{original_domain}"
                            " -> "
                            f"{transformed_domain}"
                        ),
                    }
                )

        # ----------------------------------------------------
        # OFFICIAL VALIDATOR
        # ----------------------------------------------------

        try:

            is_valid = validate_transform(
                original_url,
                transformed_url,
                code,
                benign_domains,
            )

        except Exception as exc:

            error_count += 1

            failures.append(
                {
                    "transform": code,
                    "row_index": idx,
                    "reason": (
                        "validator_exception"
                    ),
                    "original_url": original_url,
                    "transformed_url": transformed_url,
                    "details": repr(exc),
                }
            )

            continue

        # ----------------------------------------------------
        # VALID / REJECTED
        # ----------------------------------------------------

        if is_valid:

            valid_count += 1

        elif (
            transformed_url
            != original_url
        ):

            failures.append(
                {
                    "transform": code,
                    "row_index": idx,
                    "reason": (
                        "validator_rejected"
                    ),
                    "original_url": original_url,
                    "transformed_url": transformed_url,
                    "details": "",
                }
            )

    # ========================================================
    # RATES
    # ========================================================

    changed_rate = (
        changed_count
        / total
        * 100
    )

    valid_rate = (
        valid_count
        / total
        * 100
    )

    # ========================================================
    # PRINT RESULT
    # ========================================================

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
        "Valid:",
        valid_count,
        f"({valid_rate:.2f}%)"
    )

    print(
        "No-op:",
        noop_count
    )

    print(
        "Errors:",
        error_count
    )

    print(
        "Too long:",
        too_long_count
    )

    if code in {
        "T1",
        "T2",
        "T3",
        "T4",
    }:

        print(
            "Registered-domain violations:",
            domain_violation_count
        )

    # ========================================================
    # SUMMARY ROW
    # ========================================================

    summary = {
        "transform": code,
        "total": total,
        "changed": changed_count,
        "changed_rate_percent": round(
            changed_rate,
            2,
        ),
        "valid": valid_count,
        "valid_rate_percent": round(
            valid_rate,
            2,
        ),
        "no_op": noop_count,
        "errors": error_count,
        "too_long": too_long_count,
        "domain_violations": (
            domain_violation_count
        ),
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
        "REAL DATA ATTACK TRANSFORM AUDIT"
    )

    print(
        "========================================"
    )

    # ========================================================
    # LOAD BENIGN DOMAIN REFERENCE
    # ========================================================

    benign_domains = (
        load_benign_domains()
    )

    # ========================================================
    # LOAD REAL MALICIOUS URL SAMPLE
    # ========================================================

    malicious_sample = (
        load_malicious_sample()
    )

    summaries = []

    all_failures = []

    # ========================================================
    # RUN T1-T7
    # ========================================================

    for code, transform_fn in (
        TRANSFORM_FUNCTIONS.items()
    ):

        summary, failures = (
            audit_transform(
                malicious_sample,
                code,
                transform_fn,
                benign_domains,
            )
        )

        summaries.append(
            summary
        )

        all_failures.extend(
            failures
        )

    # ========================================================
    # BUILD SUMMARY TABLE
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

    # --------------------------------------------------------
    # NO CRASH
    # --------------------------------------------------------

    total_errors = int(
        summary_df[
            "errors"
        ].sum()
    )

    print(
        "Total errors:",
        total_errors
    )

    assert (
        total_errors
        == 0
    ), (
        "Some transforms crashed."
    )

    # --------------------------------------------------------
    # URL LENGTH
    # --------------------------------------------------------

    total_too_long = int(
        summary_df[
            "too_long"
        ].sum()
    )

    print(
        "URLs > 2048:",
        total_too_long
    )

    assert (
        total_too_long
        == 0
    ), (
        "Some transformed URLs exceed 2048."
    )

    # --------------------------------------------------------
    # T1-T4 DOMAIN PRESERVATION
    # --------------------------------------------------------

    free_group = summary_df[
        summary_df[
            "transform"
        ].isin(
            [
                "T1",
                "T2",
                "T3",
                "T4",
            ]
        )
    ]

    domain_violations = int(
        free_group[
            "domain_violations"
        ].sum()
    )

    print(
        "T1-T4 registered-domain violations:",
        domain_violations
    )

    assert (
        domain_violations
        == 0
    ), (
        "T1-T4 changed registered domain."
    )

    # ========================================================
    # SAVE LOGS
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

    # Nếu không có failure vẫn tạo file đúng header
    if failures_df.empty:

        failures_df = pd.DataFrame(
            columns=[
                "transform",
                "row_index",
                "reason",
                "original_url",
                "transformed_url",
                "details",
            ]
        )

    failures_df.to_csv(
        OUTPUT_FAILURES,
        index=False,
    )

    # ========================================================
    # DONE
    # ========================================================

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
        "REAL DATA ATTACK AUDIT PASSED"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()