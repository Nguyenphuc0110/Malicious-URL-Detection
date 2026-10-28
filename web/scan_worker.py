
"""Run five URL models in an isolated Python process."""

import gc
import json
import math
import sys

from web.main import MODEL_FILES
from src.models.detector import URLDetector


ORDER = [
    "LR-F1",
    "RF-F1",
    "XGB-F1",
    "LR-F2",
    "SVM-F2",
]


def main():
    request = json.load(sys.stdin)
    url = request["url"]

    if not isinstance(url, str) or not url:
        raise ValueError("Invalid URL input")

    if len(MODEL_FILES) != 5 or set(ORDER) != set(MODEL_FILES):
        raise RuntimeError("Model configuration mismatch")

    predictions = {}

    for name in ORDER:
        detector = URLDetector.load(str(MODEL_FILES[name]))

        try:
            score = float(detector.score([url])[0])
            threshold = float(detector.threshold)
        finally:
            del detector
            gc.collect()

        if not math.isfinite(score) or not math.isfinite(threshold):
            raise ValueError("Invalid model prediction")

        predictions[name] = {
            "model": name,
            "score": round(score, 6),
            "threshold": round(threshold, 6),
            "suspicious": score >= threshold,
        }

    results = [predictions[name] for name in MODEL_FILES]

    print(json.dumps({"results": results}), flush=True)


if __name__ == "__main__":
    main()
