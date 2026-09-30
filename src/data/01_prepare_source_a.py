from pathlib import Path
import pandas as pd

INPUT = Path("data/raw/source_a_kaggle/malicious_phish.csv")
OUTPUT = Path("data/processed/source_a_base.csv")

df = pd.read_csv(INPUT)

# Đổi tên type -> label
df = df.rename(columns={"type": "label"})

# Thêm tên nguồn
df["source"] = "kaggle_malicious_urls"

# Chỉ giữ các cột cần thiết
df = df[["url", "label", "source"]]

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

df.to_csv(OUTPUT, index=False)

print("=== SOURCE A PREPARED ===")
print("Output:", OUTPUT)
print("Shape:", df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nClass distribution:")
print(df["label"].value_counts())

print("\nDuplicates:")
print(df["url"].duplicated().sum())