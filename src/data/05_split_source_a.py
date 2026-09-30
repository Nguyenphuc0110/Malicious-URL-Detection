from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import tldextract

from sklearn.model_selection import GroupShuffleSplit


# ============================================================
# 1. PATHS
# ============================================================

INPUT = Path(
    "data/processed/source_a_normalized.csv"
)

DEDUP_OUTPUT = Path(
    "data/processed/source_a_dedup.csv"
)

TRAIN_OUTPUT = Path(
    "data/processed/train.csv"
)

VAL_OUTPUT = Path(
    "data/processed/val.csv"
)

TEST_OUTPUT = Path(
    "data/processed/test_A.csv"
)

LOG_DIR = Path(
    "outputs/logs"
)

TABLE_DIR = Path(
    "outputs/tables"
)

CONFLICT_LOG = LOG_DIR / "source_a_conflicting_labels.csv"

INVALID_DOMAIN_LOG = LOG_DIR / "source_a_invalid_domain.csv"

SUMMARY_OUTPUT = TABLE_DIR / "source_a_split_summary.csv"


# ============================================================
# 2. TLD EXTRACTOR
# ============================================================

# Không tải Public Suffix List từ Internet.
# Dùng snapshot có sẵn trong package.
extractor = tldextract.TLDExtract(
    suffix_list_urls=None
)


# ============================================================
# 3. REGISTERED DOMAIN FUNCTION
# ============================================================

def get_registered_domain(url):

    if pd.isna(url):
        return None

    try:
        hostname = urlsplit(
            str(url)
        ).hostname

        if not hostname:
            return None

        hostname = hostname.lower()

        result = extractor(hostname)

        # Ví dụ:
        # login.example.co.uk
        # -> example.co.uk

        registered = (
            result.top_domain_under_public_suffix
        )

        # IP / localhost / suffix lạ
        if not registered:
            registered = hostname

        return registered

    except Exception:
        return None


# ============================================================
# 4. LOAD DATA
# ============================================================

print("Loading Source A...")

df = pd.read_csv(INPUT)

print("\n=== ORIGINAL DATA ===")
print("Rows:", len(df))
print("Columns:", df.columns.tolist())


# ============================================================
# 5. CHECK REQUIRED COLUMNS
# ============================================================

required = {
    "url",
    "normalized_url",
    "label",
    "source"
}

missing = required - set(df.columns)

if missing:
    raise ValueError(
        f"Missing required columns: {missing}"
    )


# ============================================================
# 6. FIND CONFLICTING LABELS
# ============================================================

# Nếu cùng một normalized URL lại mang nhiều label khác nhau,
# không được tùy tiện giữ một label.

label_counts = (
    df.groupby("normalized_url")["label"]
    .nunique()
)

conflicting_urls = label_counts[
    label_counts > 1
].index

conflicts = df[
    df["normalized_url"].isin(
        conflicting_urls
    )
].copy()

LOG_DIR.mkdir(
    parents=True,
    exist_ok=True
)

conflicts.to_csv(
    CONFLICT_LOG,
    index=False
)

print("\n=== LABEL CONFLICT CHECK ===")

print(
    "Conflicting normalized URLs:",
    len(conflicting_urls)
)

print(
    "Rows involved in conflicts:",
    len(conflicts)
)


# ============================================================
# 7. REMOVE CONFLICTS
# ============================================================

rows_before_conflict = len(df)

df = df[
    ~df["normalized_url"].isin(
        conflicting_urls
    )
].copy()

print(
    "Rows removed because of label conflicts:",
    rows_before_conflict - len(df)
)


# ============================================================
# 8. REMOVE DUPLICATE URLS
# ============================================================

rows_before_dedup = len(df)

df = (
    df.drop_duplicates(
        subset=["normalized_url"],
        keep="first"
    )
    .reset_index(drop=True)
)

duplicates_removed = (
    rows_before_dedup - len(df)
)

print("\n=== DEDUPLICATION ===")

print(
    "Rows before dedup:",
    rows_before_dedup
)

print(
    "Duplicate URLs removed:",
    duplicates_removed
)

print(
    "Rows after dedup:",
    len(df)
)


# ============================================================
# 9. REGISTERED DOMAIN
# ============================================================

print("\nExtracting registered domains...")

df["registered_domain"] = (
    df["normalized_url"]
    .apply(get_registered_domain)
)

invalid_domain = df[
    df["registered_domain"].isna()
].copy()

invalid_domain.to_csv(
    INVALID_DOMAIN_LOG,
    index=False
)

print("\n=== DOMAIN EXTRACTION ===")

print(
    "Invalid domains:",
    len(invalid_domain)
)

df = (
    df.dropna(
        subset=["registered_domain"]
    )
    .reset_index(drop=True)
)

print(
    "Valid rows:",
    len(df)
)

print(
    "Unique registered domains:",
    df["registered_domain"].nunique()
)


# ============================================================
# 10. SAVE CLEAN DEDUP DATASET
# ============================================================

DEDUP_OUTPUT.parent.mkdir(
    parents=True,
    exist_ok=True
)

df.to_csv(
    DEDUP_OUTPUT,
    index=False
)


# ============================================================
# 11. SPLIT 70% TRAIN / 30% TEMP BY DOMAIN
# ============================================================

groups = df["registered_domain"]

split_train = GroupShuffleSplit(
    n_splits=1,
    train_size=0.70,
    random_state=42
)

train_idx, temp_idx = next(
    split_train.split(
        df,
        groups=groups
    )
)

train = (
    df.iloc[train_idx]
    .copy()
    .reset_index(drop=True)
)

temp = (
    df.iloc[temp_idx]
    .copy()
    .reset_index(drop=True)
)


# ============================================================
# 12. SPLIT TEMP 50/50
#
# 30% temp -> 15% val + 15% test
# ============================================================

temp_groups = temp[
    "registered_domain"
]

split_temp = GroupShuffleSplit(
    n_splits=1,
    train_size=0.50,
    random_state=42
)

val_idx, test_idx = next(
    split_temp.split(
        temp,
        groups=temp_groups
    )
)

val = (
    temp.iloc[val_idx]
    .copy()
    .reset_index(drop=True)
)

test = (
    temp.iloc[test_idx]
    .copy()
    .reset_index(drop=True)
)


# ============================================================
# 13. LEAKAGE CHECK
# ============================================================

train_domains = set(
    train["registered_domain"]
)

val_domains = set(
    val["registered_domain"]
)

test_domains = set(
    test["registered_domain"]
)

train_val_overlap = (
    train_domains & val_domains
)

train_test_overlap = (
    train_domains & test_domains
)

val_test_overlap = (
    val_domains & test_domains
)


print("\n=== DOMAIN LEAKAGE CHECK ===")

print(
    "Train ∩ Val:",
    len(train_val_overlap)
)

print(
    "Train ∩ Test:",
    len(train_test_overlap)
)

print(
    "Val ∩ Test:",
    len(val_test_overlap)
)


# ============================================================
# 14. URL LEAKAGE CHECK
# ============================================================

train_urls = set(
    train["normalized_url"]
)

val_urls = set(
    val["normalized_url"]
)

test_urls = set(
    test["normalized_url"]
)

print("\n=== URL LEAKAGE CHECK ===")

print(
    "Train URL ∩ Val URL:",
    len(train_urls & val_urls)
)

print(
    "Train URL ∩ Test URL:",
    len(train_urls & test_urls)
)

print(
    "Val URL ∩ Test URL:",
    len(val_urls & test_urls)
)


# ============================================================
# 15. SAFETY ASSERTIONS
# ============================================================

assert len(train_val_overlap) == 0
assert len(train_test_overlap) == 0
assert len(val_test_overlap) == 0

assert len(train_urls & val_urls) == 0
assert len(train_urls & test_urls) == 0
assert len(val_urls & test_urls) == 0


# ============================================================
# 16. SAVE SPLITS
# ============================================================

train.to_csv(
    TRAIN_OUTPUT,
    index=False
)

val.to_csv(
    VAL_OUTPUT,
    index=False
)

test.to_csv(
    TEST_OUTPUT,
    index=False
)


# ============================================================
# 17. REPORT FUNCTION
# ============================================================

def print_split_info(name, data):

    print(
        f"\n=== {name} ==="
    )

    print(
        "Rows:",
        len(data)
    )

    print(
        "Domains:",
        data[
            "registered_domain"
        ].nunique()
    )

    print(
        "\nClass distribution:"
    )

    print(
        data["label"]
        .value_counts()
    )

    print(
        "\nClass percentage:"
    )

    print(
        (
            data["label"]
            .value_counts(
                normalize=True
            )
            * 100
        ).round(2)
    )


print_split_info(
    "TRAIN",
    train
)

print_split_info(
    "VALIDATION",
    val
)

print_split_info(
    "TEST A",
    test
)


# ============================================================
# 18. SUMMARY TABLE
# ============================================================

summary = pd.DataFrame({
    "split": [
        "train",
        "validation",
        "test_A"
    ],

    "rows": [
        len(train),
        len(val),
        len(test)
    ],

    "domains": [
        train[
            "registered_domain"
        ].nunique(),

        val[
            "registered_domain"
        ].nunique(),

        test[
            "registered_domain"
        ].nunique()
    ]
})

summary["row_percentage"] = (
    summary["rows"]
    / len(df)
    * 100
).round(2)

TABLE_DIR.mkdir(
    parents=True,
    exist_ok=True
)

summary.to_csv(
    SUMMARY_OUTPUT,
    index=False
)


# ============================================================
# 19. FINAL REPORT
# ============================================================

print(
    "\n===================================="
)

print(
    "SOURCE A SPLIT COMPLETE"
)

print(
    "===================================="
)

print(
    "\nRows after final cleaning:",
    len(df)
)

print(
    "Unique domains:",
    df["registered_domain"].nunique()
)

print("\nOutputs:")

print(
    DEDUP_OUTPUT
)

print(
    TRAIN_OUTPUT
)

print(
    VAL_OUTPUT
)

print(
    TEST_OUTPUT
)

print(
    SUMMARY_OUTPUT
)

print("\nLogs:")

print(
    CONFLICT_LOG
)

print(
    INVALID_DOMAIN_LOG
)