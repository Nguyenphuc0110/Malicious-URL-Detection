import gc
import hashlib
import random
from pathlib import Path

import numpy as np
import pandas as pd

from src.attack.transforms import T1_add_param_or_path, validate_transform
from src.models.detector import URLDetector

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data/processed/handoff/test_A.csv"
OUTPUT = ROOT / "reports/d3_t1_row_level_20261027.csv"

if OUTPUT.exists():
    raise SystemExit("STOP: Output already exists. No overwrite.")

df = pd.read_csv(DATA, usecols=["url", "label"], low_memory=False)

labels = pd.to_numeric(df["label"], errors="coerce")
malicious = df.loc[
    (labels == 1) & df["url"].notna(), "url"
].astype(str).str.strip()

malicious = malicious[malicious != ""]

sample = malicious.sample(
    n=min(1000, len(malicious)),
    random_state=42
)

urls = sample.tolist()

random.seed(42)

attacked = []
valid_flags = []

for url in urls:
    try:
        candidate = T1_add_param_or_path(url)
        valid = bool(validate_transform(url, candidate, "T1", set()))
    except Exception:
        candidate = url
        valid = False

    attacked.append(candidate if valid else url)
    valid_flags.append(valid)

valid = np.asarray(valid_flags, dtype=bool)


def evaluate(filename):
    detector = URLDetector.load(str(ROOT / "models" / filename))
    threshold = float(detector.threshold)

    def scores(values):
        chunks = []
        for i in range(0, len(values), 64):
            result = np.asarray(
                detector.score(values[i:i + 64]),
                dtype=np.float64
            ).reshape(-1)

            if not np.isfinite(result).all():
                raise ValueError("Invalid model score")

            chunks.append(result)

        return np.concatenate(chunks)

    before = scores(urls)
    after = scores(attacked)

    del detector
    gc.collect()

    return before, after, threshold


print("=== EXPORT D3 ROW LEVEL RESULTS ===", flush=True)

base_before, base_after, base_threshold = evaluate("xgb_f1.joblib")
d3_before, d3_after, d3_threshold = evaluate("xgb_f1_d3.joblib")

base_b = base_before >= base_threshold
base_a = base_after >= base_threshold
d3_b = d3_before >= d3_threshold
d3_a = d3_after >= d3_threshold

common = valid & base_b & d3_b
base_lost = common & ~base_a
d3_lost = common & ~d3_a

d3_wins = common & ~base_a & d3_a
baseline_wins = common & base_a & ~d3_a

counts = {
    "SAMPLE": len(urls),
    "VALID_T1": int(valid.sum()),
    "BASELINE_BEFORE": int(base_b.sum()),
    "D3_BEFORE": int(d3_b.sum()),
    "COMMON": int(common.sum()),
    "BASELINE_LOST": int(base_lost.sum()),
    "D3_LOST": int(d3_lost.sum()),
    "D3_WINS": int(d3_wins.sum()),
    "BASELINE_WINS": int(baseline_wins.sum()),
}

expected = {
    "SAMPLE": 1000,
    "VALID_T1": 1000,
    "BASELINE_BEFORE": 514,
    "D3_BEFORE": 505,
    "COMMON": 499,
    "BASELINE_LOST": 190,
    "D3_LOST": 124,
    "D3_WINS": 72,
    "BASELINE_WINS": 6,
}

for key, value in counts.items():
    print(f"{key}: {value}", flush=True)

if counts != expected:
    raise SystemExit(
        "STOP: Results differ from previous experiment. "
        "CSV was not saved."
    )

def sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

result = pd.DataFrame({
    "sample_id": np.arange(1, len(urls) + 1),
    "source_row_index": sample.index.to_numpy(),
    "original_url_sha256": [sha256(u) for u in urls],
    "attacked_url_sha256": [sha256(u) for u in attacked],
    "t1_valid": valid.astype(int),
    "baseline_before_score": base_before,
    "baseline_after_score": base_after,
    "baseline_threshold": base_threshold,
    "baseline_before_alert": base_b.astype(int),
    "baseline_after_alert": base_a.astype(int),
    "d3_before_score": d3_before,
    "d3_after_score": d3_after,
    "d3_threshold": d3_threshold,
    "d3_before_alert": d3_b.astype(int),
    "d3_after_alert": d3_a.astype(int),
    "common_eligible": common.astype(int),
    "baseline_lost_alert": base_lost.astype(int),
    "d3_lost_alert": d3_lost.astype(int),
    "d3_win": d3_wins.astype(int),
    "baseline_win": baseline_wins.astype(int),
})

result.to_csv(OUTPUT, index=False, encoding="utf-8-sig")

print("FILE:", OUTPUT)
print("ROWS:", len(result))
print("RAW URLS SAVED: NO")
print("=== D3 ROW LEVEL EXPORT COMPLETE ===")
