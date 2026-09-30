from pathlib import Path
import pandas as pd

INPUT = Path(
    "data/raw/source_b_phiusiil/"
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)

print("=== PHIUSIIL CHECK ===")

if not INPUT.exists():
    raise FileNotFoundError(f"Không tìm thấy: {INPUT}")

df = pd.read_csv(INPUT)

print("\nShape:")
print(df.shape)

print("\nNumber of columns:")
print(len(df.columns))

print("\nImportant columns:")
print(df[["URL", "label"]].head())

print("\nMissing values:")
print(df[["URL", "label"]].isna().sum())

print("\nLabel distribution:")
print(df["label"].value_counts())

print("\nDuplicate URLs:")
print(df["URL"].duplicated().sum())