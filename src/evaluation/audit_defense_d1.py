from pathlib import Path
import importlib.util

import pandas as pd


# ============================================================
# LOAD DEFENSE MODULE
# ============================================================

DEFENSE_FILE = Path(
    "src/defense/01_url_canonicalization.py"
)

spec = importlib.util.spec_from_file_location(
    "url_canonicalization",
    DEFENSE_FILE
)

module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

canonicalize_url = module.canonicalize_url


# ============================================================
# DATASETS
# ============================================================

FILES = {
    "val":
        Path("data/processed/handoff/val.csv"),

    "test_A":
        Path("data/processed/handoff/test_A.csv"),

    "test_B":
        Path("data/processed/handoff/test_B.csv"),
}


# ============================================================
# AUDIT
# ============================================================

for name, path in FILES.items():

    if not path.exists():
        print(
            f"\n{name}: file not found, skipped"
        )
        continue

    print(
        f"\n=== {name} ==="
    )

    df = pd.read_csv(
        path,
        usecols=["url", "label"]
    )

    df["canonical_url"] = (
        df["url"]
        .apply(canonicalize_url)
    )

    df["changed"] = (
        df["url"]
        != df["canonical_url"]
    )

    df["failed"] = (
        df["canonical_url"].isna()
    )

    print(
        "Rows:",
        len(df)
    )

    print(
        "Changed:",
        int(df["changed"].sum())
    )

    print(
        "Changed %:",
        round(
            df["changed"].mean() * 100,
            2
        )
    )

    print(
        "Failed:",
        int(df["failed"].sum())
    )

    print(
        "\nChanged by label:"
    )

    for label in [0, 1]:

        subset = df[
            df["label"] == label
        ]

        if len(subset) == 0:
            continue

        print(
            f"label {label}: "
            f"{subset['changed'].mean() * 100:.2f}%"
        )


    print(
        "\nExamples:"
    )

    examples = df[
        df["changed"]
    ][
        ["url", "canonical_url"]
    ].head(10)

    print(
        examples.to_string(
            index=False
        )
    )