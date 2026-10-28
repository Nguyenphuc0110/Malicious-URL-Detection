import hashlib
import os
import re
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]

CHECKSUM_FILE = ROOT / "models" / "rf_f1.sha256"

MODEL_URL = (
    "https://github.com/Nguyenphuc0110/"
    "Malicious-URL-Detection/releases/download/"
    "original-baseline-rf-20261028/rf_f1.joblib"
)

MODEL_PATH = Path(
    os.environ.get(
        "RF_F1_MODEL_PATH",
        str(ROOT / "models" / "rf_f1.joblib"),
    )
).expanduser()


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(
            lambda: file.read(4 * 1024 * 1024),
            b"",
        ):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    expected = CHECKSUM_FILE.read_text(
        encoding="utf-8-sig"
    ).split()[0].lower()

    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError("Invalid SHA256 file")

    MODEL_PATH.parent.mkdir(
        parents=True, exist_ok=True
    )

    if MODEL_PATH.is_file():
        if file_hash(MODEL_PATH) != expected:
            raise RuntimeError(
                "Existing RF-F1 checksum mismatch"
            )

        print("RF-F1 EXISTING MODEL VERIFIED", flush=True)
        return

    print("DOWNLOADING RF-F1...", flush=True)

    temp = MODEL_PATH.with_name(
        MODEL_PATH.name + ".partial"
    )

    temp.unlink(missing_ok=True)

    request = Request(
        MODEL_URL,
        headers={"User-Agent": "AIC211-Model-Deployment"},
    )

    try:
        digest = hashlib.sha256()

        with urlopen(request, timeout=120) as response:
            with temp.open("wb") as output:
                while True:
                    chunk = response.read(4 * 1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
                    digest.update(chunk)

        if digest.hexdigest() != expected:
            raise RuntimeError(
                "Downloaded RF-F1 checksum mismatch"
            )

        os.replace(temp, MODEL_PATH)

    finally:
        temp.unlink(missing_ok=True)

    print("RF-F1 DOWNLOAD VERIFIED", flush=True)
    print("MODEL PATH:", MODEL_PATH, flush=True)


if __name__ == "__main__":
    main()
