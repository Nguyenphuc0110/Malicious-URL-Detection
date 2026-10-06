from pathlib import Path
from urllib.parse import urlsplit
import json
import random
import time

import pandas as pd
import requests
import tldextract

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ============================================================
# CONFIG
# ============================================================

TRANCO_FILE = Path(
    "data/raw/source_c/tranco/top-1m.csv"
)

TRAIN_A = Path(
    "data/processed/handoff/train.csv"
)

OUTPUT = Path(
    "data/raw/source_c_commoncrawl_benign.csv"
)

# Mục tiêu cuối
TARGET_URLS = 40000

# Số domain Tranco tối đa sẽ thử
MAX_DOMAINS = 2500

# Tối đa URL lấy từ mỗi domain
PER_DOMAIN_LIMIT = 50

# Nghỉ giữa các request để tránh spam server
SLEEP_SECONDS = 0.6

RANDOM_SEED = 42

# Common Crawl crawl đã dùng thành công trước đó
CRAWL_ID = "CC-MAIN-2026-39"

INDEX_URL = (
    f"https://index.commoncrawl.org/"
    f"{CRAWL_ID}-index"
)


# ============================================================
# SETUP
# ============================================================

random.seed(RANDOM_SEED)

extractor = tldextract.TLDExtract(
    suffix_list_urls=None
)

session = requests.Session()

session.headers.update({
    "User-Agent":
        "Malicious-URL-Detection-Academic-Research/1.0"
})


# ============================================================
# RETRY CONFIG
# ============================================================

retry_strategy = Retry(
    total=2,
    connect=2,
    read=2,
    backoff_factor=1.0,
    status_forcelist=[
        429,
        500,
        502,
        503,
        504
    ],
    allowed_methods=[
        "GET"
    ]
)

adapter = HTTPAdapter(
    max_retries=retry_strategy
)

session.mount(
    "https://",
    adapter
)

session.mount(
    "http://",
    adapter
)


# ============================================================
# HELPERS
# ============================================================

def get_registered_domain(url):
    """
    Trích registered domain.

    Ví dụ:
    news.example.com
        -> example.com
    """

    try:

        host = urlsplit(
            str(url)
        ).hostname

        if not host:
            return None

        host = host.lower()

        ext = extractor(host)

        registered = (
            ext.top_domain_under_public_suffix
        )

        return (
            registered
            if registered
            else host
        )

    except Exception:
        return None


def has_real_path(url):
    """
    Chỉ chấp nhận URL:
    - http / https
    - có path thật

    Không nhận:
        https://example.com
        https://example.com/

    Nhận:
        https://example.com/news/article
    """

    try:

        parsed = urlsplit(
            str(url)
        )

        if parsed.scheme not in (
            "http",
            "https"
        ):
            return False

        if not parsed.hostname:
            return False

        path = parsed.path

        return path not in (
            "",
            "/"
        )

    except Exception:
        return False


def save_checkpoint(results):
    """
    Lưu dữ liệu hiện tại.
    Không tạo CSV rỗng nếu chưa thu được URL nào.
    """

    if len(results) == 0:
        return

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    pd.DataFrame(
        results
    ).to_csv(
        OUTPUT,
        index=False
    )


# ============================================================
# COMMON CRAWL INFO
# ============================================================

print(
    "Using:",
    CRAWL_ID
)

print(
    "Index:",
    INDEX_URL
)


# ============================================================
# LOAD TRANCO
# ============================================================

print(
    "\nLoading Tranco domains..."
)

tranco = pd.read_csv(
    TRANCO_FILE,
    header=None,
    names=[
        "rank",
        "domain"
    ]
)

tranco["domain"] = (
    tranco["domain"]
    .astype(str)
    .str.strip()
    .str.lower()
)

tranco = tranco.dropna(
    subset=["domain"]
)

tranco = tranco.drop_duplicates(
    subset=["domain"]
)

print(
    "Tranco domains:",
    len(tranco)
)


# ============================================================
# LOAD SOURCE A TRAIN DOMAINS
# ============================================================

print(
    "\nLoading Source A train domains..."
)

train = pd.read_csv(
    TRAIN_A,
    usecols=[
        "registered_domain"
    ]
)

train_domains = set(
    train["registered_domain"]
    .dropna()
    .astype(str)
    .str.strip()
    .str.lower()
)

print(
    "Train A unique domains:",
    len(train_domains)
)


# ============================================================
# REMOVE DOMAIN OVERLAP WITH TRAIN A
# ============================================================

domains = [
    d
    for d in tranco["domain"]
    if d not in train_domains
]

print(
    "Tranco domains not seen in train A:",
    len(domains)
)


# ============================================================
# RANDOM SAMPLE OF DOMAINS
# ============================================================

random.shuffle(domains)

domains = domains[
    :MAX_DOMAINS
]

print(
    "Domains selected:",
    len(domains)
)


# ============================================================
# RESUME EXISTING OUTPUT
# ============================================================

results = []

seen_urls = set()

seen_domains_from_output = set()


if (
    OUTPUT.exists()
    and OUTPUT.stat().st_size > 0
):

    try:

        old = pd.read_csv(
            OUTPUT
        )

        if (
            len(old) > 0
            and "url" in old.columns
        ):

            results = (
                old.to_dict(
                    "records"
                )
            )

            seen_urls = set(
                old["url"]
                .dropna()
                .astype(str)
            )

            if (
                "registered_domain"
                in old.columns
            ):

                seen_domains_from_output = set(
                    old[
                        "registered_domain"
                    ]
                    .dropna()
                    .astype(str)
                    .str.lower()
                )

            print(
                "\nResuming existing output:"
            )

            print(
                "Existing URLs:",
                len(results)
            )

            print(
                "Existing domains:",
                len(
                    seen_domains_from_output
                )
            )

    except pd.errors.EmptyDataError:

        print(
            "\nExisting output is empty. "
            "Starting fresh."
        )

        results = []

        seen_urls = set()

    except Exception as e:

        print(
            "\nCould not load old checkpoint:"
        )

        print(
            type(e).__name__,
            str(e)
        )

        print(
            "Starting fresh."
        )

        results = []

        seen_urls = set()


# ============================================================
# STOP IF ALREADY ENOUGH
# ============================================================

if len(results) >= TARGET_URLS:

    print(
        "\nTarget already reached."
    )

else:

    # ========================================================
    # QUERY COMMON CRAWL
    # ========================================================

    for i, domain in enumerate(
        domains,
        start=1
    ):

        if len(results) >= TARGET_URLS:
            break

        print(
            f"[{i}/{len(domains)}] "
            f"{domain} | "
            f"collected={len(results)}"
        )

        params = {
            "url":
                f"*.{domain}",

            "output":
                "json",

            "filter": [
                "status:200",
                "mime:text/html"
            ],

            "collapse":
                "urlkey",

            "limit":
                PER_DOMAIN_LIMIT
        }

        try:

            response = session.get(
                INDEX_URL,
                params=params,
                timeout=20
            )

            # -----------------------------------------------
            # HTTP ERROR
            # -----------------------------------------------

            if response.status_code != 200:

                print(
                    "  skipped HTTP:",
                    response.status_code
                )

                time.sleep(
                    SLEEP_SECONDS
                )

                continue


            # -----------------------------------------------
            # PARSE RESULTS
            # -----------------------------------------------

            domain_added = 0

            for line in (
                response.text
                .strip()
                .splitlines()
            ):

                if not line:
                    continue

                try:

                    item = json.loads(
                        line
                    )

                except json.JSONDecodeError:
                    continue


                url = item.get(
                    "url"
                )

                if not url:
                    continue


                # -------------------------------------------
                # URL phải có path thật
                # -------------------------------------------

                if not has_real_path(
                    url
                ):
                    continue


                # -------------------------------------------
                # Registered domain
                # -------------------------------------------

                rd = (
                    get_registered_domain(
                        url
                    )
                )

                if not rd:
                    continue

                rd = rd.lower()


                # -------------------------------------------
                # Phải thuộc đúng domain đang query
                # -------------------------------------------

                if rd != domain:
                    continue


                # -------------------------------------------
                # Không được nằm trong train A
                # -------------------------------------------

                if rd in train_domains:
                    continue


                # -------------------------------------------
                # Dedup URL
                # -------------------------------------------

                if url in seen_urls:
                    continue


                seen_urls.add(
                    url
                )

                results.append({
                    "url":
                        url,

                    "label":
                        "benign",

                    "source":
                        "tranco_commoncrawl",

                    "registered_domain":
                        rd,

                    "crawl":
                        CRAWL_ID
                })

                domain_added += 1


                if (
                    len(results)
                    >= TARGET_URLS
                ):
                    break


            if domain_added > 0:

                print(
                    "  added:",
                    domain_added
                )


        except requests.exceptions.ConnectTimeout:

            print(
                "  ConnectTimeout"
            )


        except requests.exceptions.ReadTimeout:

            print(
                "  ReadTimeout"
            )


        except requests.exceptions.ConnectionError as e:

            print(
                "  ConnectionError:",
                str(e)[:120]
            )


        except requests.exceptions.RequestException as e:

            print(
                "  RequestException:",
                str(e)[:120]
            )


        except Exception as e:

            print(
                "  error:",
                type(e).__name__,
                str(e)[:120]
            )


        # ====================================================
        # CHECKPOINT
        # ====================================================

        if i % 25 == 0:

            save_checkpoint(
                results
            )

            print(
                "  checkpoint saved:",
                len(results)
            )


        time.sleep(
            SLEEP_SECONDS
        )


# ============================================================
# FINAL SAVE
# ============================================================

save_checkpoint(
    results
)


# ============================================================
# FINAL REPORT
# ============================================================

print(
    "\n===================================="
)

print(
    "SOURCE C BENIGN COLLECTION COMPLETE"
)

print(
    "===================================="
)

print(
    "Rows:",
    len(results)
)


if len(results) > 0:

    out = pd.DataFrame(
        results
    )

    unique_domains = (
        out[
            "registered_domain"
        ]
        .nunique()
    )

    duplicate_urls = (
        out[
            "url"
        ]
        .duplicated()
        .sum()
    )

    path_ratio = (
        out[
            "url"
        ]
        .apply(
            has_real_path
        )
        .mean()
        * 100
    )

    domain_overlap = (
        set(
            out[
                "registered_domain"
            ]
            .astype(str)
            .str.lower()
        )
        &
        train_domains
    )


    print(
        "Unique domains:",
        unique_domains
    )

    print(
        "Duplicate URLs:",
        duplicate_urls
    )

    print(
        "Path ratio:",
        round(
            path_ratio,
            2
        )
    )

    print(
        "Domain overlap with train A:",
        len(
            domain_overlap
        )
    )


print(
    "\nOutput:"
)

print(
    OUTPUT
)