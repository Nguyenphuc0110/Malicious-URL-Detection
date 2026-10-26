"""AIC211 URL Detector - FastAPI backend."""

import math
import json
import subprocess
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))



app = FastAPI(title="AIC211 URL Detector API")

MODEL_FILES = {
    "LR-F2-PhishingAware": ROOT / "models" / "lr_f2_phishing_aware.joblib",
    "XGB-F1-D3 (Adversarial Training)": ROOT / "models" / "xgb_f1_d3.joblib",
    "XGB-F1 Baseline": ROOT / "models" / "xgb_f1.joblib",
    "LR-F2-MultiSource": ROOT / "models" / "lr_f2_multisource.joblib",
    "LR-F1F2-Robust": ROOT / "models" / "lr_f1f2_robust.joblib",
}

class ScanRequest(BaseModel):
    url: str


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


SCAN_LOCK = threading.Lock()


@app.post("/api/scan")
def scan(request: ScanRequest):
    url = validate_url(request.url)

    if not SCAN_LOCK.acquire(blocking=False):
        raise HTTPException(
            status_code=429,
            detail="Another scan is running. Please retry shortly.",
        )

    try:
        try:
            process = subprocess.run(
                [sys.executable, "-m", "web.scan_worker"],
                input=json.dumps({"url": url}),
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=120,
                cwd=str(ROOT),
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(
                status_code=504,
                detail="The AI scan timed out. Please retry.",
            )
        except OSError:
            raise HTTPException(
                status_code=503,
                detail="Unable to start the AI worker.",
            )

        if process.returncode != 0:
            raise HTTPException(
                status_code=503,
                detail="Unable to analyze this URL. Please retry.",
            )

        try:
            payload = json.loads(process.stdout)
            results = payload["results"]

            if (
                not isinstance(results, list)
                or len(results) != len(MODEL_FILES)
            ):
                raise ValueError("Incorrect result count")

            if not all(isinstance(item, dict) for item in results):
                raise ValueError("Invalid result format")

            if [item.get("model") for item in results] != list(MODEL_FILES):
                raise ValueError("Unexpected model names")

            for item in results:
                score = item["score"]
                threshold = item["threshold"]

                if (
                    isinstance(score, bool)
                    or isinstance(threshold, bool)
                    or not isinstance(score, (int, float))
                    or not isinstance(threshold, (int, float))
                    or not math.isfinite(score)
                    or not math.isfinite(threshold)
                    or not 0 <= score <= 1
                    or not 0 <= threshold <= 1
                    or not isinstance(item.get("suspicious"), bool)
                ):
                    raise ValueError("Invalid prediction")

        except (ValueError, TypeError, KeyError):
            raise HTTPException(
                status_code=503,
                detail="Invalid response from AI worker.",
            )

        return {"results": results}

    finally:
        SCAN_LOCK.release()

app.mount(
    "/",
    StaticFiles(
        directory=str(ROOT / "web" / "static"),
        html=True,
    ),
    name="frontend",
)
