import gc
import random
import runpy
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import idna
import numpy as np
import pandas as pd

from src.attack.transforms import (
    T7_homoglyph_punycode,
    validate_transform,
)
from src.models.detector import URLDetector
from web.main import MODEL_FILES

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data/processed/handoff/test_A.csv"
OUTPUT = ROOT / "reports/d2_t7_row_level_20261027.csv"

if OUTPUT.exists():
    raise SystemExit("STOP: Output already exists.")

expected = {
    "LR-F2-PhishingAware": (348, 66, 0),
    "XGB-F1-D3 (Adversarial Training)": (354, 101, 0),
    "XGB-F1 Baseline": (359, 118, 0),
    "LR-F2-MultiSource": (283, 7, 0),
    "LR-F1F2-Robust": (283, 19, 0),
    "VOTING 2/5": (504, 47, 0),
}

if set(MODEL_FILES) != set(expected) - {"VOTING 2/5"}:
    raise SystemExit("STOP: Unexpected model configuration.")

d2 = runpy.run_path(
    str(ROOT / "src/defense/02_homoglyph_normalization.py")
)
normalize_host = d2["normalize_homoglyph_host"]


def apply_d2(url):
    try:
        parsed = urlsplit(url)
        host = parsed.hostname

        if (
            not host
            or ":" in host
            or "@" in parsed.netloc
            or "[" in parsed.netloc
        ):
            return url

        decoded = idna.decode(host)
        normalized = normalize_host(decoded)

        if (
            not isinstance(normalized, str)
            or not normalized
            or normalized == decoded
        ):
            return url

        netloc = normalized
        if parsed.port is not None:
            netloc += f":{parsed.port}"

        return urlunsplit((
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        ))

    except (idna.IDNAError, ValueError, TypeError):
        return url


df = pd.read_csv(
    DATA,
    usecols=["url", "label"],
    low_memory=False,
)

labels = pd.to_numeric(df["label"], errors="coerce")

malicious = df.loc[
    (labels == 1) & df["url"].notna(),
    "url",
].astype(str).str.strip()

malicious = malicious[malicious != ""]

sample = malicious.sample(
    n=min(1000, len(malicious)),
    random_state=42,
)

random.seed(42)

pairs = []
invalid = 0
decode_errors = 0

for sample_id, (row_index, url) in enumerate(
    sample.items(), start=1
):
    try:
        attacked = T7_homoglyph_punycode(url)

        if not validate_transform(
            url, attacked, "T7", set()
        ):
            invalid += 1
            continue

        host = urlsplit(attacked).hostname

        if not host:
            invalid += 1
            continue

        try:
            idna.decode(host)
        except (idna.IDNAError, ValueError):
            decode_errors += 1
            continue

        pairs.append((
            sample_id,
            row_index,
            url,
            attacked,
        ))

    except Exception:
        invalid += 1


if not pairs:
    raise SystemExit("STOP: No valid T7 pairs.")

originals = [p[2] for p in pairs]
attacked_urls = [p[3] for p in pairs]

d2_originals = [apply_d2(u) for u in originals]
d2_attacked = [apply_d2(u) for u in attacked_urls]

n = len(pairs)

changed_original = sum(
    a != b for a, b in zip(originals, d2_originals)
)
changed_attacked = sum(
    a != b for a, b in zip(attacked_urls, d2_attacked)
)
restored = sum(
    a == b for a, b in zip(originals, d2_attacked)
)

print("=== D2 ROW LEVEL EVALUATION ===", flush=True)
print("ORIGINAL SAMPLE:", len(sample))
print("EVALUATED PAIRS:", n)
print("INVALID:", invalid)
print("DECODE ERRORS:", decode_errors)
print("D2 CHANGED ORIGINAL:", changed_original)
print("D2 CHANGED T7:", changed_attacked)
print("D2 RESTORED FULL URL:", restored)

if (
    len(sample) != 1000
    or n != 814
    or invalid != 180
    or decode_errors != 6
    or changed_original != 0
    or changed_attacked != 814
    or restored != 814
):
    raise SystemExit(
        "STOP: T7/D2 sample differs from previous test. "
        "No CSV saved."
    )


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
    "sample_id": [p[0] for p in pairs],
    "source_row_index": [p[1] for p in pairs],
    "d2_original_changed": [
        int(a != b)
        for a, b in zip(originals, d2_originals)
    ],
    "d2_attacked_changed": [
        int(a != b)
        for a, b in zip(attacked_urls, d2_attacked)
    ],
    "d2_restored_full_url": [
        int(a == b)
        for a, b in zip(originals, d2_attacked)
    ],
}

votes_raw_before = np.zeros(n, dtype=np.int16)
votes_raw_after = np.zeros(n, dtype=np.int16)
votes_d2_before = np.zeros(n, dtype=np.int16)
votes_d2_after = np.zeros(n, dtype=np.int16)


def save_flags(prefix, rb, ra, db, da):
    eligible = rb & db
    raw_lost = eligible & ~ra
    d2_lost = eligible & ~da

    rows[prefix + "_raw_before_alert"] = rb.astype(int)
    rows[prefix + "_raw_after_alert"] = ra.astype(int)
    rows[prefix + "_d2_before_alert"] = db.astype(int)
    rows[prefix + "_d2_after_alert"] = da.astype(int)
    rows[prefix + "_eligible"] = eligible.astype(int)
    rows[prefix + "_raw_lost"] = raw_lost.astype(int)
    rows[prefix + "_d2_lost"] = d2_lost.astype(int)

    return (
        int(eligible.sum()),
        int(raw_lost.sum()),
        int(d2_lost.sum()),
    )


def verify(name, actual):
    print(
        f"{name}: "
        f"ELIGIBLE={actual[0]} "
        f"RAW_LOST={actual[1]} "
        f"D2_LOST={actual[2]}",
        flush=True,
    )

    if actual != expected[name]:
        raise SystemExit(
            f"STOP: Result mismatch for {name}. "
            "No CSV saved."
        )


for i, (name, path) in enumerate(
    MODEL_FILES.items(), start=1
):
    model = URLDetector.load(str(path))
    threshold = float(model.threshold)

    raw_before_score = scores(model, originals)
    raw_after_score = scores(model, attacked_urls)
    d2_before_score = scores(model, d2_originals)
    d2_after_score = scores(model, d2_attacked)

    rb = raw_before_score >= threshold
    ra = raw_after_score >= threshold
    db = d2_before_score >= threshold
    da = d2_after_score >= threshold

    votes_raw_before += rb.astype(np.int16)
    votes_raw_after += ra.astype(np.int16)
    votes_d2_before += db.astype(np.int16)
    votes_d2_after += da.astype(np.int16)

    prefix = f"m{i:02d}"

    rows[prefix + "_threshold"] = threshold
    rows[prefix + "_raw_before_score"] = raw_before_score
    rows[prefix + "_raw_after_score"] = raw_after_score
    rows[prefix + "_d2_before_score"] = d2_before_score
    rows[prefix + "_d2_after_score"] = d2_after_score

    verify(
        name,
        save_flags(prefix, rb, ra, db, da),
    )

    print(f"COLUMN PREFIX {prefix}: {name}", flush=True)

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
        votes_d2_before >= 2,
        votes_d2_after >= 2,
    ),
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
print("URL HASHES SAVED: NO")
print("=== D2 ROW LEVEL EXPORT COMPLETE ===")
