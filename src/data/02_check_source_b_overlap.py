from pathlib import Path
import pandas as pd

SOURCE_A = Path("data/processed/source_a_base.csv")
SOURCE_B_2025 = Path("data/raw/source_b_2025.csv")
SOURCE_B_PHIUSIIL = Path("data/raw/source_b_phiusiil.csv")

a = pd.read_csv(SOURCE_A)
b2025 = pd.read_csv(SOURCE_B_2025)
phiusiil = pd.read_csv(SOURCE_B_PHIUSIIL)

def clean_urls(series):
    return (
        series.astype(str)
        .str.strip()
        .str.lower()
    )

a_benign = set(
    clean_urls(
        a.loc[a["label"] == "benign", "url"]
    )
)

b2025_benign = set(
    clean_urls(
        b2025.loc[b2025["label"] == "benign", "url"]
    )
)

phiusiil_benign = set(
    clean_urls(
        phiusiil.loc[phiusiil["label"] == "benign", "url"]
    )
)

overlap_2025 = a_benign & b2025_benign
overlap_phiusiil = a_benign & phiusiil_benign

print("=== SOURCE B BENIGN OVERLAP CHECK ===")

print("\nSource A benign:", len(a_benign))

print("\nSource B 2025 benign:", len(b2025_benign))
print("Overlap A vs B2025:", len(overlap_2025))

print("\nPhiUSIIL benign:", len(phiusiil_benign))
print("Overlap A vs PhiUSIIL:", len(overlap_phiusiil))