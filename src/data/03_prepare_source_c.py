from pathlib import Path
import pandas as pd

OPENPHISH = Path(
    "data/raw/source_c/openphish/openphish.txt"
)

PHISHTANK = Path(
    "data/raw/source_c/phishtank/online-valid.csv"
)

TRANCO = Path(
    "data/raw/source_c/tranco/top-1m.csv"
)

OUT_MALICIOUS = Path(
    "data/processed/source_c_malicious.csv"
)

OUT_BENIGN = Path(
    "data/processed/source_c_benign.csv"
)

# =========================
# 1. OpenPhish
# =========================
with open(
    OPENPHISH,
    "r",
    encoding="utf-8",
    errors="ignore"
) as f:
    openphish_urls = [
        line.strip()
        for line in f
        if line.strip()
    ]

openphish_df = pd.DataFrame({
    "url": openphish_urls,
    "label": "phishing",
    "source": "openphish"
})

# =========================
# 2. PhishTank
# =========================
phishtank_raw = pd.read_csv(
    PHISHTANK,
    usecols=["url"]
)

phishtank_df = pd.DataFrame({
    "url": phishtank_raw["url"],
    "label": "phishing",
    "source": "phishtank"
})

# =========================
# 3. Merge malicious
# =========================
malicious = pd.concat(
    [
        openphish_df,
        phishtank_df
    ],
    ignore_index=True
)

# =========================
# 4. Tranco
# =========================
tranco_raw = pd.read_csv(
    TRANCO,
    header=None,
    names=["rank", "domain"]
)

# Tranco là domain, thêm scheme
tranco_df = pd.DataFrame()

tranco_df["url"] = (
    "https://" +
    tranco_raw["domain"].astype(str)
)

tranco_df["label"] = "benign"
tranco_df["source"] = "tranco"

# =========================
# 5. Save
# =========================
OUT_MALICIOUS.parent.mkdir(
    parents=True,
    exist_ok=True
)

malicious.to_csv(
    OUT_MALICIOUS,
    index=False
)

tranco_df.to_csv(
    OUT_BENIGN,
    index=False
)

# =========================
# 6. Report
# =========================
print("=== SOURCE C PREPARED ===")

print("\nMalicious:")
print(malicious.shape)
print(malicious["source"].value_counts())

print("\nBenign:")
print(tranco_df.shape)

print("\nMissing malicious:")
print(malicious.isna().sum())

print("\nMissing benign:")
print(tranco_df.isna().sum())

print("\nOutput:")
print(OUT_MALICIOUS)
print(OUT_BENIGN)