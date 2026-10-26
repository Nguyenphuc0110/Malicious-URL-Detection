"""AIC211 URL Detector - FastAPI backend."""

import math
import sys
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.models.detector import URLDetector


app = FastAPI(title="AIC211 URL Detector API")

MODEL_FILES = {
    "LR-F2-PhishingAware": ROOT / "models" / "lr_f2_phishing_aware.joblib",
    "XGB-F1-D3 (Adversarial Training)": (
        ROOT / "models" / "xgb_f1_d3.joblib"
    ),
}


class ScanRequest(BaseModel):
    url: str


@lru_cache(maxsize=1)
def load_models():
    return {
        name: URLDetector.load(str(path))
        for name, path in MODEL_FILES.items()
    }


def validate_url(value):
    url = value.strip()

    if not url:
        raise HTTPException(
            status_code=400,
            detail="Bạn chưa nhập URL.",
        )

    if len(url) > 2048:
        raise HTTPException(
            status_code=400,
            detail="URL vượt quá 2048 ký tự.",
        )

    if any(char.isspace() for char in url):
        raise HTTPException(
            status_code=400,
            detail="URL không được chứa khoảng trắng.",
        )

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Unsupported scheme")

        if not parsed.hostname:
            raise ValueError("Missing hostname")

        _ = parsed.port

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="URL không hợp lệ. Hãy dùng http:// hoặc https://.",
        )

    return url


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
def scan(request: ScanRequest):
    url = validate_url(request.url)

    try:
        models = load_models()
        results = []

        for name, detector in models.items():
            score = float(detector.score([url])[0])
            threshold = float(detector.threshold)

            if not math.isfinite(score):
                raise ValueError("Invalid model score")

            results.append({
                "model": name,
                "score": round(score, 6),
                "threshold": round(threshold, 6),
                "suspicious": score >= threshold,
            })

        return {"results": results}

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Không thể phân tích URL. Vui lòng thử lại.",
        )


app.mount(
    "/",
    StaticFiles(
        directory=str(ROOT / "web" / "static"),
        html=True,
    ),
    name="frontend",
)
