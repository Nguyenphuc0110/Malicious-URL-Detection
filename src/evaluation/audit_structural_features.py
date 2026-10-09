from pathlib import Path
import importlib.util

import numpy as np
import pandas as pd


# ============================================================
# CONFIG
# ============================================================

RANDOM_SEED = 42

# Audit trước 5,000 URL mỗi dataset.
# Sau khi pass có thể đổi thành None để audit toàn bộ.
SAMPLE_SIZE_PER_DATASET = 5000

DATASETS = {
    "train": Path(
        "data/processed/handoff/train.csv"
    ),
    "val": Path(
        "data/processed/handoff/val.csv"
    ),
    "test_A": Path(
        "data/processed/handoff/test_A.csv"
    ),
    "test_B": Path(
        "data/processed/handoff/test_B.csv"
    ),
    "test_C": Path(
        "data/processed/handoff/test_C.csv"
    ),
}

STRUCTURAL_FEATURES_FILE = Path(
    "src/defense/03_structural_features.py"
)

OUTPUT_SUMMARY = Path(
    "outputs/logs/"
    "structural_features_audit_summary.csv"
)

OUTPUT_FAILURES = Path(
    "outputs/logs/"
    "structural_features_audit_failures.csv"
)


# ============================================================
# LOAD STRUCTURAL FEATURES MODULE
# ============================================================

def load_structural_features_module():
    """
    Load 03_structural_features.py.

    Dùng importlib vì filename bắt đầu bằng số.
    """

    if not STRUCTURAL_FEATURES_FILE.exists():

        raise FileNotFoundError(
            STRUCTURAL_FEATURES_FILE
        )

    spec = importlib.util.spec_from_file_location(
        "structural_features_module",
        STRUCTURAL_FEATURES_FILE,
    )

    module = importlib.util.module_from_spec(
        spec
    )

    spec.loader.exec_module(
        module
    )

    return module


# ============================================================
# LOAD DATASET SAMPLE
# ============================================================

def load_dataset_sample(
    name,
    path,
):
    """
    Load dataset và lấy sample deterministic.
    """

    print(
        f"\n=== LOAD {name} ==="
    )

    if not path.exists():

        raise FileNotFoundError(
            path
        )

    df = pd.read_csv(
        path,
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
            f"{name}: missing columns "
            f"{missing}"
        )

    total_rows = len(
        df
    )

    df = df[
        df["url"].notna()
    ].copy()

    df[
        "url"
    ] = (
        df[
            "url"
        ]
        .astype(str)
        .str.strip()
    )

    df = df[
        df["url"] != ""
    ].copy()

    if (
        SAMPLE_SIZE_PER_DATASET
        is not None
        and len(df)
        > SAMPLE_SIZE_PER_DATASET
    ):

        sample = df.sample(
            n=SAMPLE_SIZE_PER_DATASET,
            random_state=RANDOM_SEED,
        ).reset_index(
            drop=True
        )

    else:

        sample = df.reset_index(
            drop=True
        )

    print(
        "Total rows:",
        f"{total_rows:,}"
    )

    print(
        "Rows audited:",
        f"{len(sample):,}"
    )

    return (
        sample,
        total_rows,
    )


# ============================================================
# AUDIT ONE DATASET
# ============================================================

def audit_dataset(
    name,
    path,
    module,
):
    """
    Audit structural feature extraction.

    Hard requirements:
      - extraction errors = 0
      - feature count = expected
      - missing values = 0
      - infinite values = 0
    """

    sample, total_rows = (
        load_dataset_sample(
            name,
            path,
        )
    )

    expected_features = (
        module.FEATURE_NAMES
    )

    feature_rows = []

    failures = []

    print(
        f"\n=== EXTRACT FEATURES: {name} ==="
    )

    # ========================================================
    # EXTRACT ONE URL AT A TIME
    # ========================================================

    for idx, row in (
        sample.iterrows()
    ):

        url = str(
            row["url"]
        )

        try:

            features = (
                module
                .extract_structural_features(
                    url
                )
            )

            feature_rows.append(
                features
            )

        except Exception as exc:

            failures.append(
                {
                    "dataset": name,
                    "row_index": idx,
                    "url": url,
                    "reason": (
                        "extraction_exception"
                    ),
                    "details": repr(
                        exc
                    ),
                }
            )

    # ========================================================
    # BUILD FEATURE DATAFRAME
    # ========================================================

    feature_df = pd.DataFrame(
        feature_rows,
        columns=expected_features,
    )

    extraction_errors = len(
        failures
    )

    feature_count = len(
        feature_df.columns
    )

    # ========================================================
    # COLUMN CHECK
    # ========================================================

    columns_match = (
        list(
            feature_df.columns
        )
        == list(
            expected_features
        )
    )

    # ========================================================
    # MISSING VALUES
    # ========================================================

    if len(
        feature_df
    ) > 0:

        missing_values = int(
            feature_df
            .isna()
            .sum()
            .sum()
        )

    else:

        missing_values = 0

    # ========================================================
    # INFINITE VALUES
    # ========================================================

    if len(
        feature_df
    ) > 0:

        numeric_array = (
            feature_df
            .astype(float)
            .to_numpy()
        )

        infinite_values = int(
            np.isinf(
                numeric_array
            ).sum()
        )

    else:

        infinite_values = 0

    # ========================================================
    # NEGATIVE COUNTS
    # ========================================================

    count_features = [
        "url_length",
        "hostname_length",
        "path_length",
        "query_length",
        "fragment_length",
        "num_subdomains",
        "num_dots",
        "num_hyphens",
        "num_underscores",
        "num_slashes",
        "num_digits",
        "num_letters",
        "num_special_chars",
        "num_query_params",
        "path_depth",
        "num_percent_encoded",
    ]

    negative_count_values = 0

    for feature in count_features:

        if feature in feature_df.columns:

            negative_count_values += int(
                (
                    feature_df[
                        feature
                    ]
                    < 0
                ).sum()
            )

    # ========================================================
    # RATIO RANGE
    # ========================================================

    ratio_violations = 0

    for feature in [
        "digit_ratio",
        "letter_ratio",
    ]:

        if feature in feature_df.columns:

            ratio_violations += int(
                (
                    (
                        feature_df[
                            feature
                        ]
                        < 0
                    )
                    |
                    (
                        feature_df[
                            feature
                        ]
                        > 1
                    )
                ).sum()
            )

    # ========================================================
    # BOOLEAN RANGE
    # ========================================================

    boolean_violations = 0

    for feature in [
        "has_ip_host",
        "has_https",
        "has_port",
        "has_userinfo",
    ]:

        if feature in feature_df.columns:

            boolean_violations += int(
                (
                    ~feature_df[
                        feature
                    ].isin(
                        [
                            0,
                            1,
                        ]
                    )
                ).sum()
            )

    # ========================================================
    # PRINT
    # ========================================================

    print(
        "Feature rows:",
        len(
            feature_df
        )
    )

    print(
        "Feature count:",
        feature_count
    )

    print(
        "Columns match:",
        columns_match
    )

    print(
        "Extraction errors:",
        extraction_errors
    )

    print(
        "Missing feature values:",
        missing_values
    )

    print(
        "Infinite values:",
        infinite_values
    )

    print(
        "Negative count values:",
        negative_count_values
    )

    print(
        "Ratio violations:",
        ratio_violations
    )

    print(
        "Boolean violations:",
        boolean_violations
    )

    # ========================================================
    # SUMMARY ROW
    # ========================================================

    summary = {
        "dataset": name,
        "total_rows": total_rows,
        "rows_audited": len(
            sample
        ),
        "feature_rows": len(
            feature_df
        ),
        "feature_count": (
            feature_count
        ),
        "columns_match": (
            columns_match
        ),
        "extraction_errors": (
            extraction_errors
        ),
        "missing_values": (
            missing_values
        ),
        "infinite_values": (
            infinite_values
        ),
        "negative_count_values": (
            negative_count_values
        ),
        "ratio_violations": (
            ratio_violations
        ),
        "boolean_violations": (
            boolean_violations
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

    print(
        "========================================"
    )

    print(
        "DEFENSE D2 STRUCTURAL FEATURES AUDIT"
    )

    print(
        "========================================"
    )

    module = (
        load_structural_features_module()
    )

    print(
        "\nExpected feature count:",
        len(
            module.FEATURE_NAMES
        )
    )

    summaries = []

    all_failures = []

    # ========================================================
    # AUDIT ALL DATASETS
    # ========================================================

    for name, path in (
        DATASETS.items()
    ):

        summary, failures = (
            audit_dataset(
                name,
                path,
                module,
            )
        )

        summaries.append(
            summary
        )

        all_failures.extend(
            failures
        )

    summary_df = pd.DataFrame(
        summaries
    )

    # ========================================================
    # SUMMARY
    # ========================================================

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
            "extraction_errors"
        ].sum()
    )

    total_missing = int(
        summary_df[
            "missing_values"
        ].sum()
    )

    total_inf = int(
        summary_df[
            "infinite_values"
        ].sum()
    )

    total_negative = int(
        summary_df[
            "negative_count_values"
        ].sum()
    )

    total_ratio_violations = int(
        summary_df[
            "ratio_violations"
        ].sum()
    )

    total_boolean_violations = int(
        summary_df[
            "boolean_violations"
        ].sum()
    )

    all_columns_match = bool(
        summary_df[
            "columns_match"
        ].all()
    )

    print(
        "Extraction errors:",
        total_errors
    )

    print(
        "Missing values:",
        total_missing
    )

    print(
        "Infinite values:",
        total_inf
    )

    print(
        "Negative count values:",
        total_negative
    )

    print(
        "Ratio violations:",
        total_ratio_violations
    )

    print(
        "Boolean violations:",
        total_boolean_violations
    )

    print(
        "All columns match:",
        all_columns_match
    )

    assert (
        total_errors
        == 0
    )

    assert (
        total_missing
        == 0
    )

    assert (
        total_inf
        == 0
    )

    assert (
        total_negative
        == 0
    )

    assert (
        total_ratio_violations
        == 0
    )

    assert (
        total_boolean_violations
        == 0
    )

    assert (
        all_columns_match
        is True
    )

    assert (
        (
            summary_df[
                "feature_count"
            ]
            == len(
                module.FEATURE_NAMES
            )
        ).all()
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

    if failures_df.empty:

        failures_df = pd.DataFrame(
            columns=[
                "dataset",
                "row_index",
                "url",
                "reason",
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
        "STRUCTURAL FEATURES AUDIT PASSED"
    )

    print(
        "========================================"
    )


if __name__ == "__main__":
    main()