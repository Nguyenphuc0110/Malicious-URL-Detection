from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pandas as pd


# ============================================================
# 1. INPUT PATHS
# ============================================================

SOURCE_A = Path(
    "data/processed/source_a_base.csv"
)

SOURCE_B_2025 = Path(
    "data/raw/source_b_2025.csv"
)

SOURCE_B_PHIUSIIL = Path(
    "data/raw/source_b_phiusiil.csv"
)

SOURCE_C_MALICIOUS = Path(
    "data/processed/source_c_malicious.csv"
)

SOURCE_C_BENIGN = Path(
    "data/processed/source_c_benign.csv"
)


# ============================================================
# 2. OUTPUT PATHS
# ============================================================

OUTPUT_A = Path(
    "data/processed/source_a_normalized.csv"
)

OUTPUT_B = Path(
    "data/processed/source_b_normalized.csv"
)

OUTPUT_C = Path(
    "data/processed/source_c_normalized.csv"
)

LOG_DIR = Path(
    "outputs/logs"
)

LOG_A_FAILED = LOG_DIR / "source_a_normalization_failed.csv"
LOG_B_FAILED = LOG_DIR / "source_b_normalization_failed.csv"
LOG_C_FAILED = LOG_DIR / "source_c_normalization_failed.csv"


# ============================================================
# 3. NORMALIZE FUNCTION
# ============================================================

def normalize_url(url):
    """
    Normalize URL while keeping information useful for ML.

    Rules:
    - Remove leading/trailing whitespace
    - Add http:// if scheme is missing
    - Lowercase scheme
    - Lowercase hostname
    - Preserve path
    - Preserve query string
    - Preserve non-default port
    - Remove fragment (#...)
    """

    if pd.isna(url):
        return None

    url = str(url).strip()

    if not url:
        return None

    # Add scheme if missing
    if "://" not in url:
        url = "http://" + url

    try:
        parts = urlsplit(url)

        scheme = parts.scheme.lower()

        hostname = parts.hostname

        if not hostname:
            return None

        hostname = hostname.lower()

        # Check port
        try:
            port = parts.port
        except ValueError:
            return None

        # Remove default ports
        if (
            (scheme == "http" and port == 80)
            or
            (scheme == "https" and port == 443)
        ):
            port = None

        if port:
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        path = parts.path
        query = parts.query

        # Fragment intentionally removed
        fragment = ""

        normalized = urlunsplit(
            (
                scheme,
                netloc,
                path,
                query,
                fragment,
            )
        )

        return normalized

    except Exception:
        return None


# ============================================================
# 4. PROCESS FUNCTION
# ============================================================

def process_dataset(df, name, failed_log):
    """
    Normalize one dataset and remove rows that cannot
    be normalized.

    Failed rows are saved to outputs/logs/.
    """

    df = df.copy()

    rows_before = len(df)

    # Normalize
    df["normalized_url"] = df["url"].apply(
        normalize_url
    )

    # Find failed rows
    failed = df[
        df["normalized_url"].isna()
    ].copy()

    failed_count = len(failed)

    # Save failed URLs
    failed_log.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    failed.to_csv(
        failed_log,
        index=False
    )

    # Remove failed rows
    cleaned = df.dropna(
        subset=["normalized_url"]
    ).reset_index(drop=True)

    rows_after = len(cleaned)

    # Report
    print(f"\n=== {name} ===")

    print("Rows before:", rows_before)

    print(
        "Normalization failed:",
        failed_count
    )

    print(
        "Rows after:",
        rows_after
    )

    print(
        "Missing after cleaning:",
        cleaned["normalized_url"]
        .isna()
        .sum()
    )

    print("\nExamples:")

    print(
        cleaned[
            [
                "url",
                "normalized_url"
            ]
        ].head(10)
    )

    print(
        "\nFailed log:",
        failed_log
    )

    return cleaned


# ============================================================
# 5. LOAD SOURCE A
# ============================================================

print("Loading Source A...")

a = pd.read_csv(
    SOURCE_A
)


# ============================================================
# 6. LOAD + MERGE SOURCE B
# ============================================================

print("Loading Source B...")

b2025 = pd.read_csv(
    SOURCE_B_2025
)

b_phiusiil = pd.read_csv(
    SOURCE_B_PHIUSIIL
)

b = pd.concat(
    [
        b2025,
        b_phiusiil
    ],
    ignore_index=True
)


# ============================================================
# 7. LOAD + MERGE SOURCE C
# ============================================================

print("Loading Source C...")

c_malicious = pd.read_csv(
    SOURCE_C_MALICIOUS
)

c_benign = pd.read_csv(
    SOURCE_C_BENIGN
)

c = pd.concat(
    [
        c_malicious,
        c_benign
    ],
    ignore_index=True
)


# ============================================================
# 8. CHECK REQUIRED COLUMNS
# ============================================================

datasets = {
    "SOURCE A": a,
    "SOURCE B": b,
    "SOURCE C": c,
}

required_columns = {
    "url",
    "label",
    "source",
}

for name, df in datasets.items():

    missing_columns = (
        required_columns
        - set(df.columns)
    )

    if missing_columns:
        raise ValueError(
            f"{name} missing columns: "
            f"{missing_columns}"
        )


# ============================================================
# 9. NORMALIZE
# ============================================================

a = process_dataset(
    a,
    "SOURCE A",
    LOG_A_FAILED
)

b = process_dataset(
    b,
    "SOURCE B",
    LOG_B_FAILED
)

c = process_dataset(
    c,
    "SOURCE C",
    LOG_C_FAILED
)


# ============================================================
# 10. SAVE NORMALIZED DATASETS
# ============================================================

OUTPUT_A.parent.mkdir(
    parents=True,
    exist_ok=True
)

a.to_csv(
    OUTPUT_A,
    index=False
)

b.to_csv(
    OUTPUT_B,
    index=False
)

c.to_csv(
    OUTPUT_C,
    index=False
)


# ============================================================
# 11. FINAL REPORT
# ============================================================

print(
    "\n===================================="
)

print(
    "NORMALIZATION COMPLETE"
)

print(
    "===================================="
)

print("\nSource A:")
print("Rows:", len(a))
print("Output:", OUTPUT_A)

print("\nSource B:")
print("Rows:", len(b))
print("Output:", OUTPUT_B)

print("\nSource C:")
print("Rows:", len(c))
print("Output:", OUTPUT_C)

print("\nFailed normalization logs:")

print(LOG_A_FAILED)
print(LOG_B_FAILED)
print(LOG_C_FAILED)