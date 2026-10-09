from pathlib import Path
import importlib.util

import pandas as pd


# ============================================================
# CONFIG
# ============================================================

CANONICALIZATION_FILE = Path(
    "src/defense/01_url_canonicalization.py"
)

FILES = {
    "val":
        Path("data/processed/handoff/val.csv"),

    "test_A":
        Path("data/processed/handoff/test_A.csv"),

    "test_B":
        Path("data/processed/handoff/test_B.csv"),

    "test_C":
        Path("data/processed/handoff/test_C.csv"),
}

EXAMPLE_COUNT = 10


# ============================================================
# LOAD DEFENSE D1 MODULE
# ============================================================

def load_canonicalization_module():
    """
    Load 01_url_canonicalization.py bằng importlib
    vì tên file bắt đầu bằng số.
    """

    if not CANONICALIZATION_FILE.exists():
        raise FileNotFoundError(
            CANONICALIZATION_FILE
        )

    spec = importlib.util.spec_from_file_location(
        "url_canonicalization_module",
        CANONICALIZATION_FILE,
    )

    if spec is None or spec.loader is None:
        raise ImportError(
            "Cannot load canonicalization module."
        )

    module = importlib.util.module_from_spec(
        spec
    )

    spec.loader.exec_module(
        module
    )

    if not hasattr(
        module,
        "canonicalize_url",
    ):
        raise AttributeError(
            "01_url_canonicalization.py "
            "does not define canonicalize_url()."
        )

    return module


# ============================================================
# AUDIT ONE DATASET
# ============================================================

def audit_dataset(
    name,
    path,
    canonicalize_url,
):
    """
    Audit Defense D1 canonicalization trên một dataset.

    Kiểm tra:
      - tổng số rows
      - số URL bị thay đổi
      - changed %
      - số URL canonicalization bị lỗi
      - changed % theo label
      - ví dụ URL trước/sau
    """

    print(
        f"\n=== {name} ==="
    )

    if not path.exists():
        raise FileNotFoundError(
            path
        )

    df = pd.read_csv(
        path,
        low_memory=False,
    )

    required_columns = {
        "url",
        "label",
    }

    missing_columns = (
        required_columns
        - set(df.columns)
    )

    if missing_columns:
        raise ValueError(
            f"{name}: missing columns "
            f"{missing_columns}"
        )

    total_rows = len(
        df
    )

    canonical_urls = []
    failed_flags = []

    # ========================================================
    # CANONICALIZE
    # ========================================================

    for value in df["url"]:

        if pd.isna(value):

            canonical_urls.append(
                None
            )

            failed_flags.append(
                True
            )

            continue

        url = str(
            value
        )

        try:

            canonical = canonicalize_url(
                url
            )

            # Nếu function trả None thì tính là failed.
            if canonical is None:

                canonical_urls.append(
                    None
                )

                failed_flags.append(
                    True
                )

            else:

                canonical_urls.append(
                    str(canonical)
                )

                failed_flags.append(
                    False
                )

        except Exception:

            canonical_urls.append(
                None
            )

            failed_flags.append(
                True
            )

    # ========================================================
    # ADD TEMP COLUMNS
    # ========================================================

    audit_df = df.copy()

    audit_df[
        "canonical_url"
    ] = canonical_urls

    audit_df[
        "failed"
    ] = failed_flags

    audit_df[
        "changed"
    ] = (
        ~audit_df[
            "failed"
        ]
        & (
            audit_df[
                "url"
            ].astype(str)
            != audit_df[
                "canonical_url"
            ].astype(str)
        )
    )

    # ========================================================
    # COUNTS
    # ========================================================

    changed_count = int(
        audit_df[
            "changed"
        ].sum()
    )

    failed_count = int(
        audit_df[
            "failed"
        ].sum()
    )

    changed_percent = (
        changed_count
        / total_rows
        * 100
        if total_rows > 0
        else 0.0
    )

    # ========================================================
    # MAIN OUTPUT
    # ========================================================

    print(
        "Rows:",
        total_rows
    )

    print(
        "Changed:",
        changed_count
    )

    print(
        "Changed %:",
        f"{changed_percent:.2f}"
    )

    print(
        "Failed:",
        failed_count
    )

    # ========================================================
    # CHANGED BY LABEL
    # ========================================================

    print(
        "\nChanged by label:"
    )

    labels = sorted(
        audit_df[
            "label"
        ]
        .dropna()
        .unique()
        .tolist()
    )

    for label in labels:

        subset = audit_df[
            audit_df[
                "label"
            ] == label
        ]

        if len(
            subset
        ) == 0:

            changed_label_percent = 0.0

        else:

            changed_label_percent = (
                subset[
                    "changed"
                ].mean()
                * 100
            )

        print(
            f"label {label}: "
            f"{changed_label_percent:.2f}%"
        )

    # ========================================================
    # EXAMPLES
    # ========================================================

    print(
        "\nExamples:"
    )

    examples = audit_df[
        audit_df[
            "changed"
        ]
    ][
        [
            "url",
            "canonical_url",
        ]
    ].head(
        EXAMPLE_COUNT
    )

    if examples.empty:

        print(
            "No changed URLs."
        )

    else:

        print(
            examples.to_string(
                index=False
            )
        )

    # ========================================================
    # HARD CHECK
    # ========================================================

    assert (
        failed_count
        == 0
    ), (
        f"{name}: canonicalization "
        f"failed for {failed_count} URLs"
    )

    return {
        "dataset": name,
        "rows": total_rows,
        "changed": changed_count,
        "changed_percent": round(
            changed_percent,
            2,
        ),
        "failed": failed_count,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    # ========================================================
    # LOAD D1
    # ========================================================

    module = (
        load_canonicalization_module()
    )

    canonicalize_url = (
        module.canonicalize_url
    )

    summaries = []

    # ========================================================
    # AUDIT VAL / TEST A / TEST B / TEST C
    # ========================================================

    for name, path in (
        FILES.items()
    ):

        result = audit_dataset(
            name,
            path,
            canonicalize_url,
        )

        summaries.append(
            result
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
        "DEFENSE D1 AUDIT SUMMARY"
    )

    print(
        "========================================"
    )

    print(
        summary_df.to_string(
            index=False
        )
    )

    total_failed = int(
        summary_df[
            "failed"
        ].sum()
    )

    print(
        "\nTotal failed:",
        total_failed
    )

    assert (
        total_failed
        == 0
    )

    print(
        "\n========================================"
    )

    print(
        "DEFENSE D1 AUDIT PASSED"
    )

    print(
        "========================================"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()