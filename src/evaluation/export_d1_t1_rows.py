import gc
import hashlib
import random
from pathlib import Path

import numpy as np
import pandas as pd

from src.attack.transforms import T1_add_param_or_path, validate_transform
from src.evaluation.audit_defense_d1 import load_canonicalization_module
from src.models.detector import URLDetector
from web.main import MODEL_FILES

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data/processed/handoff/test_A.csv"
OUTPUT = ROOT / "reports/d1_t1_row_level_20261027.csv"

if OUTPUT.exists():
    raise SystemExit("STOP: Output already exists.")

expected = {
    "LR-F2-PhishingAware": (502, 140, 108),
    "XGB-F1-D3 (Adversarial Training)": (503, 127, 100),
    "XGB-F1 Baseline": (513, 205, 129),
    "LR-F2-MultiSource": (428, 119, 82),
    "LR-F1F2-Robust": (428, 124, 94),
    "VOTING 2/5": (667, 208, 141),
}

if set(MODEL_FILES) != set(expected) - {"VOTING 2/5"}:
    raise SystemExit("STOP: Model list differs from previous test.")

random.seed(42)

df = pd.read_csv(
    DATA,
    usecols=["url", "label"],
    low_memory=False,
)

labels = pd.to_numeric(df["label"], errors="coerce")

malicious = df.loc[
    (labels == 1) & df["url"].notna(), "url"
].astype(str).str.strip()

malicious = malicious[malicious != ""]

sample = malicious.sample(
    n=min(1000, len(malicious)),
    random_state=42,
)

urls = sample.tolist()
n = len(urls)

attacked = []
valid_flags = []

for url in urls:
    try:
        candidate = T1_add_param_or_path(url)
        valid = bool(
            validate_transform(url, candidate, "T1", set())
        )
    except Exception:
        candidate = url
        valid = False

    attacked.append(candidate if valid else url)
    valid_flags.append(valid)

valid = np.asarray(valid_flags, dtype=bool)

canonicalize = load_canonicalization_module().canonicalize_url

original_d1_raw = [canonicalize(u) for u in urls]
attacked_d1_raw = [canonicalize(u) for u in attacked]

canonical_ok = np.asarray([
    a is not None and b is not None
    for a, b in zip(original_d1_raw, attacked_d1_raw)
], dtype=bool)

d1_originals = [
    a if a is not None else u
    for a, u in zip(original_d1_raw, urls)
]

d1_attacked = [
    a if a is not None else u
    for a, u in zip(attacked_d1_raw, attacked)
]


def sha256(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def scores(detector, values):
    chunks = []

    for i in range(0, len(values), 64):
        result = np.asarray(
            detector.score(values[i:i + 64]),
            dtype=np.float64,
        ).reshape(-1)

        if not np.isfinite(result).all():
            raise ValueError("Invalid model score.")

        chunks.append(result)

    return np.concatenate(chunks)


rows = {
    "sample_id": np.arange(1, n + 1),
    "source_row_index": sample.index.to_numpy(),
    "original_url_sha256": [sha256(u) for u in urls],
    "attacked_url_sha256": [sha256(u) for u in attacked],
    "t1_valid": valid.astype(int),
    "d1_pair_valid": canonical_ok.astype(int),
    "d1_original_changed": np.asarray([
        a != b for a, b in zip(urls, d1_originals)
    ], dtype=int),
    "d1_attacked_changed": np.asarray([
        a != b for a, b in zip(attacked, d1_attacked)
    ], dtype=int),
    "d1_pair_equal": np.asarray([
        a == b for a, b in zip(d1_originals, d1_attacked)
    ], dtype=int),
}

votes_raw_before = np.zeros(n, dtype=np.int16)
votes_raw_after = np.zeros(n, dtype=np.int16)
votes_d1_before = np.zeros(n, dtype=np.int16)
votes_d1_after = np.zeros(n, dtype=np.int16)


def save_flags(prefix, rb, ra, db, da):
    eligible = valid & canonical_ok & rb & db
    raw_lost = eligible & ~ra
    d1_lost = eligible & ~da

    rows[prefix + "_raw_before_alert"] = rb.astype(int)
    rows[prefix + "_raw_after_alert"] = ra.astype(int)
    rows[prefix + "_d1_before_alert"] = db.astype(int)
    rows[prefix + "_d1_after_alert"] = da.astype(int)
    rows[prefix + "_eligible"] = eligible.astype(int)
    rows[prefix + "_raw_lost"] = raw_lost.astype(int)
    rows[prefix + "_d1_lost"] = d1_lost.astype(int)

    return (
        int(eligible.sum()),
        int(raw_lost.sum()),
        int(d1_lost.sum()),
    )


def verify(name, actual):
    print(
        f"{name}: "
        f"ELIGIBLE={actual[0]} "
        f"RAW_LOST={actual[1]} "
        f"D1_LOST={actual[2]}",
        flush=True,
    )

    if actual != expected[name]:
        raise SystemExit(
            f"STOP: Results do not match previous test for {name}. "
            "CSV was not saved."
        )


print("=== D1 ROW LEVEL EVALUATION ===", flush=True)
print("SAMPLE:", n)
print("VALID T1:", int(valid.sum()))
print("VALID D1 PAIRS:", int(canonical_ok.sum()))

for i, (name, path) in enumerate(MODEL_FILES.items(), start=1):
    model = URLDetector.load(str(path))
    threshold = float(model.threshold)

    raw_before_score = scores(model, urls)
    raw_after_score = scores(model, attacked)
    d1_before_score = scores(model, d1_originals)
    d1_after_score = scores(model, d1_attacked)

    rb = raw_before_score >= threshold
    ra = raw_after_score >= threshold
    db = d1_before_score >= threshold
    da = d1_after_score >= threshold

    votes_raw_before += rb.astype(np.int16)
    votes_raw_after += ra.astype(np.int16)
    votes_d1_before += db.astype(np.int16)
    votes_d1_after += da.astype(np.int16)

    prefix = f"m{i:02d}"

    rows[prefix + "_threshold"] = threshold
    rows[prefix + "_raw_before_score"] = raw_before_score
    rows[prefix + "_raw_after_score"] = raw_after_score
    rows[prefix + "_d1_before_score"] = d1_before_score
    rows[prefix + "_d1_after_score"] = d1_after_score

    verify(
        name,
        save_flags(prefix, rb, ra, db, da),
    )

    print(f"  COLUMN PREFIX {prefix}: {name}", flush=True)

    del model
    gc.collect()

print()
print("=== WEBSITE VOTING 2/5 ===")

verify(
    "VOTING 2/5",
    save_flags(
        "voting_2of5",
        votes_raw_before >= 2,
        votes_raw_after >= 2,
        votes_d1_before >= 2,
        votes_d1_after >= 2,
    ),
)

if n != 1000 or int(valid.sum()) != 1000:
    raise SystemExit(
        "STOP: Sample or valid attack count differs. No CSV saved."
    )

if int(canonical_ok.sum()) != 1000:
    raise SystemExit(
        "STOP: Canonicalization pairs differ. No CSV saved."
    )

result = pd.DataFrame(rows)
result.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig",
)

print()
print("FILE:", OUTPUT)
print("ROWS:", len(result))
print("RAW URLS SAVED: NO")
print("=== D1 ROW LEVEL EXPORT COMPLETE ===")
