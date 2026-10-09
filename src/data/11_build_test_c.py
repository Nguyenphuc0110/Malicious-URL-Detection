from pathlib import Path
from urllib.parse import urlsplit
import ipaddress
import re

import pandas as pd
import tldextract

from url_normalization_utils import normalize_url


# ============================================================
# CONFIG
# ============================================================

RANDOM_SEED = 42
TARGET_PER_CLASS = 18_000

SOURCE_A_DEDUP = Path(
    "data/processed/source_a_dedup.csv"
)

TRAIN_A = Path(
    "data/processed/handoff/train.csv"
)

SOURCE_C_MALICIOUS = Path(
    "data/processed/source_c_malicious.csv"
)

COMMONCRAWL_BENIGN = Path(
    "data/raw/source_c_commoncrawl_benign.csv"
)

OUTPUT_FILE = Path(
    "data/processed/handoff/test_C.csv"
)


# ============================================================
# TLD EXTRACT
# ============================================================

# Offline mode:
# không tải Public Suffix List từ Internet.
TLD_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=None
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def find_url_column(df):
    """
    Tìm cột chứa URL.
    """

    candidates = [
        "normalized_url",
        "url",
        "URL",
        "Url",
        "uri",
        "link",
    ]

    for col in candidates:
        if col in df.columns:
            return col

    raise ValueError(
        "Cannot find URL column. "
        f"Available columns: {list(df.columns)}"
    )


def decode_ampersand_entity(url):
    """
    Chỉ xử lý HTML escaped ampersand.

    Ví dụ:
        &amp;       -> &
        &amp;amp;   -> &
        &amp;amp;amp; -> &

    Không dùng html.unescape() vì có thể làm thay đổi
    những chuỗi hợp lệ như &region1.
    """

    if url is None:
        return None

    url = str(url)

    # Decode tối đa 10 lớp.
    for _ in range(10):

        new_url = re.sub(
            r"&amp;",
            "&",
            url,
            flags=re.IGNORECASE,
        )

        if new_url == url:
            break

        url = new_url

    return url


def registered_domain_from_url(url):
    """
    Lấy registered domain từ URL.

    Ví dụ:
        https://abc.example.com/a
        -> example.com

    Nếu hostname là IP:
        -> trả chính IP.
    """

    if url is None:
        return None

    try:
        parsed = urlsplit(
            str(url)
        )

        host = parsed.hostname

    except Exception:
        return None

    if not host:
        return None

    host = (
        host
        .lower()
        .strip(".")
    )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    try:
        ipaddress.ip_address(
            host
        )

        return host

    except ValueError:
        pass

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    ext = TLD_EXTRACT(
        host
    )

    registered = (
        ext.top_domain_under_public_suffix
    )

    if registered:
        return registered.lower()

    # fallback cho hostname bất thường
    return host


def has_real_path(url):
    """
    URL có path thật nếu path khác:
        ""
        "/"

    Ví dụ:
        https://abc.com
        -> False

        https://abc.com/
        -> False

        https://abc.com/login
        -> True
    """

    try:
        path = urlsplit(
            str(url)
        ).path

    except Exception:
        return False

    return path not in (
        "",
        "/",
    )


def normalize_and_clean_url(url):
    """
    Pipeline URL thống nhất:

    raw
      -> cleanup &amp;
      -> normalize_url()
      -> cleanup &amp; lần nữa

    Trả None nếu normalize thất bại.
    """

    if pd.isna(url):
        return None

    url = str(
        url
    ).strip()

    if not url:
        return None

    # Cleanup trước normalize
    url = decode_ampersand_entity(
        url
    )

    # Normalize dùng chung với pipeline Source A/B/C
    url = normalize_url(
        url
    )

    if url is None:
        return None

    if pd.isna(url):
        return None

    # Cleanup lần cuối sau normalize
    url = decode_ampersand_entity(
        url
    )

    url = str(
        url
    ).strip()

    if not url:
        return None

    return url


# ============================================================
# LOAD SOURCE A REFERENCES
# ============================================================

def load_source_a_reference():
    """
    Lấy:
        1. toàn bộ URL Source A
        2. registered_domain của train A

    Dùng để ngăn:
        - exact URL overlap
        - train-domain leakage
    """

    print(
        "\n=== LOAD SOURCE A REFERENCE ==="
    )

    if not SOURCE_A_DEDUP.exists():
        raise FileNotFoundError(
            SOURCE_A_DEDUP
        )

    if not TRAIN_A.exists():
        raise FileNotFoundError(
            TRAIN_A
        )

    # --------------------------------------------------------
    # SOURCE A URL SET
    # --------------------------------------------------------

    source_a = pd.read_csv(
        SOURCE_A_DEDUP,
        low_memory=False,
    )

    source_a_url_col = find_url_column(
        source_a
    )

    source_a_urls = set(
        source_a[
            source_a_url_col
        ]
        .dropna()
        .astype(str)
        .str.strip()
    )

    # --------------------------------------------------------
    # TRAIN-A DOMAIN SET
    # --------------------------------------------------------

    train_a = pd.read_csv(
        TRAIN_A,
        usecols=[
            "registered_domain"
        ],
    )

    train_domains = set(
        train_a[
            "registered_domain"
        ]
        .dropna()
        .astype(str)
        .str.lower()
        .str.strip()
    )

    print(
        "Source A URLs:",
        len(source_a_urls)
    )

    print(
        "Train A domains:",
        len(train_domains)
    )

    return (
        source_a_urls,
        train_domains,
    )


# ============================================================
# LOAD SOURCE C MALICIOUS
# ============================================================

def load_source_c_malicious():
    """
    Load phishing/malicious URLs của Source C.
    """

    print(
        "\n=== LOAD SOURCE C MALICIOUS ==="
    )

    if not SOURCE_C_MALICIOUS.exists():
        raise FileNotFoundError(
            SOURCE_C_MALICIOUS
        )

    print(
        "Using:",
        SOURCE_C_MALICIOUS
    )

    df = pd.read_csv(
        SOURCE_C_MALICIOUS,
        low_memory=False,
    )

    url_col = find_url_column(
        df
    )

    return pd.DataFrame(
        {
            "url": df[
                url_col
            ]
        }
    )


# ============================================================
# CLEAN MALICIOUS
# ============================================================

def clean_malicious(
    malicious,
    source_a_urls,
    train_domains,
):
    """
    Clean Source C phishing:

        - normalize
        - decode &amp;
        - dedup
        - registered_domain
        - remove exact overlap Source A
        - remove train-A domain overlap
        - chỉ giữ URL có real path
    """

    print(
        "\n=== CLEAN SOURCE C MALICIOUS ==="
    )

    print(
        "Raw malicious:",
        len(malicious)
    )

    malicious = malicious.copy()

    # --------------------------------------------------------
    # NORMALIZE + CLEAN
    # --------------------------------------------------------

    malicious[
        "url"
    ] = malicious[
        "url"
    ].apply(
        normalize_and_clean_url
    )

    normalization_failed = int(
        malicious[
            "url"
        ]
        .isna()
        .sum()
    )

    print(
        "Normalization failed:",
        normalization_failed
    )

    malicious = malicious[
        malicious[
            "url"
        ].notna()
    ].copy()

    # --------------------------------------------------------
    # DEDUP SAU KHI NORMALIZE/CLEAN
    # --------------------------------------------------------

    before = len(
        malicious
    )

    malicious = (
        malicious
        .drop_duplicates(
            subset=[
                "url"
            ]
        )
        .copy()
    )

    print(
        "Internal duplicates removed:",
        before - len(malicious)
    )

    # --------------------------------------------------------
    # REGISTERED DOMAIN
    # --------------------------------------------------------

    malicious[
        "registered_domain"
    ] = malicious[
        "url"
    ].apply(
        registered_domain_from_url
    )

    missing_domain = int(
        malicious[
            "registered_domain"
        ]
        .isna()
        .sum()
    )

    print(
        "Missing registered_domain:",
        missing_domain
    )

    malicious = malicious[
        malicious[
            "registered_domain"
        ].notna()
    ].copy()

    # --------------------------------------------------------
    # EXACT URL OVERLAP SOURCE A
    # --------------------------------------------------------

    overlap_mask = malicious[
        "url"
    ].isin(
        source_a_urls
    )

    overlap_count = int(
        overlap_mask.sum()
    )

    malicious = malicious[
        ~overlap_mask
    ].copy()

    print(
        "Exact URL overlap A removed:",
        overlap_count
    )

    # --------------------------------------------------------
    # DOMAIN OVERLAP TRAIN A
    # --------------------------------------------------------

    train_domain_mask = malicious[
        "registered_domain"
    ].astype(str).str.lower().isin(
        train_domains
    )

    train_domain_count = int(
        train_domain_mask.sum()
    )

    malicious = malicious[
        ~train_domain_mask
    ].copy()

    print(
        "Train-domain overlap removed:",
        train_domain_count
    )

    # --------------------------------------------------------
    # KEEP REAL PATH ONLY
    # --------------------------------------------------------

    malicious[
        "has_path"
    ] = malicious[
        "url"
    ].apply(
        has_real_path
    )

    before_path = len(
        malicious
    )

    malicious = malicious[
        malicious[
            "has_path"
        ]
    ].copy()

    print(
        "Homepage/no-path malicious removed:",
        before_path - len(malicious)
    )

    print(
        "Clean malicious with real path:",
        len(malicious)
    )

    print(
        "Malicious unique domains:",
        malicious[
            "registered_domain"
        ].nunique()
    )

    print(
        "Malicious path ratio:",
        f"{malicious['has_path'].mean() * 100:.2f}%"
    )

    return malicious


# ============================================================
# LOAD + CLEAN COMMON CRAWL BENIGN
# ============================================================

def load_commoncrawl_benign(
    source_a_urls,
    train_domains,
):
    """
    Load benign real-path URL thu từ Common Crawl.

    Common Crawl benign ở đây là weak-label benign:
    URL lấy từ các domain được xem là benign.
    """

    print(
        "\n=== LOAD COMMON CRAWL BENIGN ==="
    )

    if not COMMONCRAWL_BENIGN.exists():
        raise FileNotFoundError(
            COMMONCRAWL_BENIGN
        )

    df = pd.read_csv(
        COMMONCRAWL_BENIGN,
        low_memory=False,
    )

    url_col = find_url_column(
        df
    )

    benign = pd.DataFrame(
        {
            "url": df[
                url_col
            ]
        }
    )

    # --------------------------------------------------------
    # NORMALIZE + CLEAN
    # --------------------------------------------------------

    benign[
        "url"
    ] = benign[
        "url"
    ].apply(
        normalize_and_clean_url
    )

    normalization_failed = int(
        benign[
            "url"
        ]
        .isna()
        .sum()
    )

    print(
        "Normalization failed:",
        normalization_failed
    )

    benign = benign[
        benign[
            "url"
        ].notna()
    ].copy()

    # --------------------------------------------------------
    # DEDUP
    # --------------------------------------------------------

    before = len(
        benign
    )

    benign = (
        benign
        .drop_duplicates(
            subset=[
                "url"
            ]
        )
        .copy()
    )

    print(
        "Internal duplicates removed:",
        before - len(benign)
    )

    # --------------------------------------------------------
    # REAL PATH ONLY
    # --------------------------------------------------------

    benign[
        "has_path"
    ] = benign[
        "url"
    ].apply(
        has_real_path
    )

    before_path = len(
        benign
    )

    benign = benign[
        benign[
            "has_path"
        ]
    ].copy()

    print(
        "Homepage/no-path benign removed:",
        before_path - len(benign)
    )

    # --------------------------------------------------------
    # REGISTERED DOMAIN
    # --------------------------------------------------------

    benign[
        "registered_domain"
    ] = benign[
        "url"
    ].apply(
        registered_domain_from_url
    )

    missing_domain = int(
        benign[
            "registered_domain"
        ]
        .isna()
        .sum()
    )

    print(
        "Missing registered_domain:",
        missing_domain
    )

    benign = benign[
        benign[
            "registered_domain"
        ].notna()
    ].copy()

    # --------------------------------------------------------
    # EXACT OVERLAP SOURCE A
    # --------------------------------------------------------

    overlap_mask = benign[
        "url"
    ].isin(
        source_a_urls
    )

    overlap_count = int(
        overlap_mask.sum()
    )

    benign = benign[
        ~overlap_mask
    ].copy()

    print(
        "Exact URL overlap A removed:",
        overlap_count
    )

    # --------------------------------------------------------
    # DOMAIN OVERLAP TRAIN A
    # --------------------------------------------------------

    train_domain_mask = benign[
        "registered_domain"
    ].astype(str).str.lower().isin(
        train_domains
    )

    train_domain_count = int(
        train_domain_mask.sum()
    )

    benign = benign[
        ~train_domain_mask
    ].copy()

    print(
        "Train-domain overlap removed:",
        train_domain_count
    )

    print(
        "Available real-path benign:",
        len(benign)
    )

    print(
        "Unique domains:",
        benign[
            "registered_domain"
        ].nunique()
    )

    print(
        "Benign path ratio:",
        f"{benign['has_path'].mean() * 100:.2f}%"
    )

    return benign


# ============================================================
# SAMPLE MALICIOUS
# ============================================================

def sample_malicious(
    malicious
):
    """
    Sample 18,000 phishing URL.
    """

    if len(
        malicious
    ) < TARGET_PER_CLASS:

        raise RuntimeError(
            "Not enough malicious real-path URLs. "
            f"Need {TARGET_PER_CLASS}, "
            f"have {len(malicious)}."
        )

    sampled = malicious.sample(
        n=TARGET_PER_CLASS,
        random_state=RANDOM_SEED,
    ).copy()

    sampled[
        "label"
    ] = 1

    sampled[
        "orig_class"
    ] = "phishing"

    return sampled


# ============================================================
# SAMPLE BENIGN
# ============================================================

def sample_benign(
    benign
):
    """
    Sample 18,000 benign URL.
    """

    if len(
        benign
    ) < TARGET_PER_CLASS:

        raise RuntimeError(
            "Not enough benign real-path URLs. "
            f"Need {TARGET_PER_CLASS}, "
            f"have {len(benign)}."
        )

    sampled = benign.sample(
        n=TARGET_PER_CLASS,
        random_state=RANDOM_SEED + 1,
    ).copy()

    sampled[
        "label"
    ] = 0

    sampled[
        "orig_class"
    ] = "benign"

    return sampled


# ============================================================
# VALIDATE FINAL TEST C
# ============================================================

def validate_final(
    final_df,
    source_a_urls,
    train_domains,
):
    """
    Kiểm tra toàn bộ test_C trước khi lưu.
    """

    print(
        "\n===================================="
    )

    print(
        "FINAL TEST C VALIDATION"
    )

    print(
        "===================================="
    )

    # --------------------------------------------------------
    # TOTAL
    # --------------------------------------------------------

    print(
        "Rows:",
        len(final_df)
    )

    # --------------------------------------------------------
    # LABEL
    # --------------------------------------------------------

    print(
        "\nLabel counts:"
    )

    print(
        final_df[
            "label"
        ]
        .value_counts()
        .sort_index()
    )

    # --------------------------------------------------------
    # ORIG CLASS
    # --------------------------------------------------------

    print(
        "\nOrig class counts:"
    )

    print(
        final_df[
            "orig_class"
        ]
        .value_counts()
    )

    # --------------------------------------------------------
    # MISSING
    # --------------------------------------------------------

    missing_url = int(
        final_df[
            "url"
        ]
        .isna()
        .sum()
    )

    missing_domain = int(
        final_df[
            "registered_domain"
        ]
        .isna()
        .sum()
    )

    print(
        "\nMissing URL:",
        missing_url
    )

    print(
        "Missing registered_domain:",
        missing_domain
    )

    # --------------------------------------------------------
    # DUPLICATE
    # --------------------------------------------------------

    duplicate_urls = int(
        final_df[
            "url"
        ]
        .duplicated()
        .sum()
    )

    print(
        "Duplicate URLs:",
        duplicate_urls
    )

    # --------------------------------------------------------
    # &amp;
    # --------------------------------------------------------

    amp_count = int(
        final_df[
            "url"
        ]
        .astype(str)
        .str.contains(
            "&amp;",
            case=False,
            regex=False,
        )
        .sum()
    )

    print(
        "URLs still containing &amp;:",
        amp_count
    )

    # --------------------------------------------------------
    # EXACT SOURCE A URL OVERLAP
    # --------------------------------------------------------

    url_overlap = int(
        final_df[
            "url"
        ]
        .isin(
            source_a_urls
        )
        .sum()
    )

    print(
        "URL overlap with Source A:",
        url_overlap
    )

    # --------------------------------------------------------
    # TRAIN-A DOMAIN OVERLAP
    # --------------------------------------------------------

    domain_overlap = int(
        final_df[
            "registered_domain"
        ]
        .astype(str)
        .str.lower()
        .isin(
            train_domains
        )
        .sum()
    )

    print(
        "Domain overlap with train A:",
        domain_overlap
    )

    # --------------------------------------------------------
    # PATH RATIO
    # --------------------------------------------------------

    temp = final_df.copy()

    temp[
        "has_path"
    ] = temp[
        "url"
    ].apply(
        has_real_path
    )

    print(
        "\nPath ratio by label:"
    )

    path_ratios = {}

    for label in [
        0,
        1,
    ]:

        subset = temp[
            temp[
                "label"
            ] == label
        ]

        ratio = (
            subset[
                "has_path"
            ].mean()
            * 100
        )

        path_ratios[
            label
        ] = ratio

        print(
            f"label {label}: "
            f"{ratio:.2f}%"
        )

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    expected_columns = [
        "url",
        "label",
        "orig_class",
        "registered_domain",
    ]

    print(
        "\nColumns:",
        list(
            final_df.columns
        )
    )

    # ========================================================
    # HARD CHECKS
    # ========================================================

    assert list(
        final_df.columns
    ) == expected_columns

    assert (
        len(final_df)
        == TARGET_PER_CLASS * 2
    )

    assert (
        final_df[
            "label"
        ]
        .value_counts()
        .get(
            0,
            0,
        )
        == TARGET_PER_CLASS
    )

    assert (
        final_df[
            "label"
        ]
        .value_counts()
        .get(
            1,
            0,
        )
        == TARGET_PER_CLASS
    )

    assert (
        missing_url
        == 0
    )

    assert (
        missing_domain
        == 0
    )

    assert (
        duplicate_urls
        == 0
    )

    assert (
        amp_count
        == 0
    )

    assert (
        url_overlap
        == 0
    )

    assert (
        domain_overlap
        == 0
    )

    assert (
        abs(
            path_ratios[
                0
            ]
            - 100.0
        )
        < 1e-9
    )

    assert (
        abs(
            path_ratios[
                1
            ]
            - 100.0
        )
        < 1e-9
    )

    print(
        "\nALL FINAL TEST C CHECKS PASSED"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "===================================="
    )

    print(
        "BUILD FINAL TEST C - REAL PATH ONLY"
    )

    print(
        "===================================="
    )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ========================================================
    # SOURCE A REFERENCE
    # ========================================================

    (
        source_a_urls,
        train_domains,
    ) = load_source_a_reference()

    # ========================================================
    # MALICIOUS
    # ========================================================

    malicious_raw = (
        load_source_c_malicious()
    )

    malicious_clean = clean_malicious(
        malicious_raw,
        source_a_urls,
        train_domains,
    )

    malicious_sample = sample_malicious(
        malicious_clean
    )

    print(
        "\n=== MALICIOUS SAMPLE ==="
    )

    print(
        "Rows:",
        len(malicious_sample)
    )

    print(
        "Path ratio:",
        f"{malicious_sample['has_path'].mean() * 100:.2f}%"
    )

    # ========================================================
    # BENIGN
    # ========================================================

    benign_clean = load_commoncrawl_benign(
        source_a_urls,
        train_domains,
    )

    benign_sample = sample_benign(
        benign_clean
    )

    print(
        "\n=== BENIGN SAMPLE ==="
    )

    print(
        "Rows:",
        len(benign_sample)
    )

    print(
        "Path ratio:",
        f"{benign_sample['has_path'].mean() * 100:.2f}%"
    )

    # ========================================================
    # FINAL COLUMNS
    # ========================================================

    final_columns = [
        "url",
        "label",
        "orig_class",
        "registered_domain",
    ]

    benign_final = benign_sample[
        final_columns
    ].copy()

    malicious_final = malicious_sample[
        final_columns
    ].copy()

    # ========================================================
    # CHECK BENIGN/MALICIOUS COLLISION
    # ========================================================

    malicious_urls = set(
        malicious_final[
            "url"
        ]
    )

    collision_mask = benign_final[
        "url"
    ].isin(
        malicious_urls
    )

    collisions = int(
        collision_mask.sum()
    )

    print(
        "\nCross-class URL collisions:",
        collisions
    )

    if collisions > 0:

        raise RuntimeError(
            "Benign/malicious URL collision detected: "
            f"{collisions}"
        )

    # ========================================================
    # COMBINE
    # ========================================================

    final_df = pd.concat(
        [
            benign_final,
            malicious_final,
        ],
        ignore_index=True,
    )

    # deterministic shuffle
    final_df = final_df.sample(
        frac=1,
        random_state=RANDOM_SEED,
    ).reset_index(
        drop=True
    )

    # ========================================================
    # FINAL VALIDATION
    # ========================================================

    validate_final(
        final_df,
        source_a_urls,
        train_domains,
    )

    # ========================================================
    # SAVE ONLY AFTER ALL CHECKS PASS
    # ========================================================

    final_df.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    print(
        "\n===================================="
    )

    print(
        "TEST C BUILD COMPLETE"
    )

    print(
        "===================================="
    )

    print(
        "Output:",
        OUTPUT_FILE
    )

    print(
        "Rows:",
        len(final_df)
    )

    print(
        "Header:",
        ",".join(
            final_df.columns
        )
    )

    print(
        "\nExample rows:"
    )

    print(
        final_df.head(
            10
        ).to_string(
            index=False
        )
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()