import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

INPUT = Path("data/processed/source_a_base.csv")
OUTPUT = Path("outputs/figures/source_a_class_distribution.png")

df = pd.read_csv(INPUT)

counts = df["label"].value_counts()

print(counts)

counts.plot(kind="bar")

plt.title("Source A Class Distribution")
plt.xlabel("Class")
plt.ylabel("Number of URLs")
plt.xticks(rotation=0)
plt.tight_layout()

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

plt.savefig(OUTPUT, dpi=300)

print("\nSaved:")
print(OUTPUT)

table_output = Path(
    "outputs/tables/source_a_class_distribution.csv"
)

table_output.parent.mkdir(
    parents=True,
    exist_ok=True
)

counts.to_csv(
    table_output,
    header=["count"]
)

plt.show()