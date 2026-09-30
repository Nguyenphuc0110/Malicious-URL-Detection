from pathlib import Path
import pandas as pd

INPUT = Path(
    "data/raw/source_b_2025_original/url_features_extracted1.csv"
)

OUTPUT = Path(
    "data/raw/source_b_2025.csv"
)

df = pd.read_csv(INPUT)

print("\nOriginal ClassLabel values:")
print(df["ClassLabel"].value_counts(dropna=False))

print("=== SOURCE B 2025 CHECK ===")
print("Shape:", df.shape)
print("Columns:", df.columns.tolist())

result = pd.DataFrame()

# Chỉ lấy URL thô
result["url"] = df["URL"]

# Chuyển label số thành tên
result["label"] = df["ClassLabel"].map({
    1: "benign",
    0: "phishing"
})

print("\nRows with unmapped label:")
print(
    df.loc[
        result["label"].isna(),
        ["URL", "ClassLabel"]
    ]
)

# Ghi nguồn
result["source"] = "legitphish_2025"

missing_before = result["label"].isna().sum()

result = result.dropna(
    subset=["url", "label"]
).reset_index(drop=True)

print(f"\nRemoved rows with missing url/label: {missing_before}")

# Tạo folder nếu chưa có
OUTPUT.parent.mkdir(
    parents=True,
    exist_ok=True
)

result.to_csv(
    OUTPUT,
    index=False
)

print("\n=== SOURCE B 2025 PREPARED ===")

print("\nShape:")
print(result.shape)

print("\nColumns:")
print(result.columns.tolist())

print("\nClass distribution:")
print(result["label"].value_counts())

print("\nMissing:")
print(result.isna().sum())

print("\nDuplicate URLs:")
print(result["url"].duplicated().sum())

print("\nOutput:")
print(OUTPUT)