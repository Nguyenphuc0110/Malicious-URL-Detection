from pathlib import Path
import pandas as pd

DATA_PATH = Path(
    "data/raw/source_a_kaggle/malicious_phish.csv"
)

print("=== SOURCE A CHECK ===\n")

# Kiểm tra file tồn tại
if not DATA_PATH.exists():
    raise FileNotFoundError(
        f"Không tìm thấy file: {DATA_PATH}"
    )

# Đọc CSV
df = pd.read_csv(DATA_PATH)

print("Shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

print("\nMissing values:")
print(df.isna().sum())

print("\nClass distribution:")
print(df["type"].value_counts())

print("\nDuplicate URLs:")
print(df["url"].duplicated().sum())