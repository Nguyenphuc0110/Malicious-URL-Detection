from pathlib import Path
import pandas as pd

INPUT = Path(
    "data/raw/source_b_phiusiil/"
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)

OUTPUT = Path(
    "data/processed/source_b_phiusiil_base.csv"
)

df = pd.read_csv(INPUT)

result = pd.DataFrame()

result["url"] = df["URL"]

result["label"] = df["label"].map({
    1: "benign",
    0: "phishing"
})

result["source"] = "phiusiil"

OUTPUT.parent.mkdir(
    parents=True,
    exist_ok=True
)

result.to_csv(
    OUTPUT,
    index=False
)

print("=== PHIUSIIL PREPARED ===")

print("\nShape:")
print(result.shape)

print("\nColumns:")
print(result.columns.tolist())

print("\nClass distribution:")
print(result["label"].value_counts())

print("\nMissing:")
print(result.isna().sum())

print("\nOutput:")
print(OUTPUT)