from pathlib import Path

DATA_DIR = Path("data/raw/iscx_url2016")

files = {
    "benign": "Benign_list_big_final.csv",
    "defacement": "DefacementSitesURLFiltered.csv",
    "malware": "Malware_dataset.csv",
    "phishing": "phishing_dataset.csv",
    "spam": "spam_dataset.csv",
}

print("=== ISCX-URL2016 RAW DATA CHECK ===\n")

for label, filename in files.items():
    path = DATA_DIR / filename

    print(f"[{label.upper()}]")
    print(f"File: {path}")

    if not path.exists():
        print("Status: MISSING\n")
        continue

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        urls = [line.strip() for line in f if line.strip()]

    print("Status: OK")
    print("Number of URLs:", len(urls))

    print("First 3 URLs:")
    for url in urls[:3]:
        print(" ", url)

    print()