from collections import Counter
from math import log2
from urllib.parse import urlsplit
import ipaddress
import re

import pandas as pd
import tldextract


# ============================================================
# TLD EXTRACT
# ============================================================

# Offline mode để không phụ thuộc Internet.
TLD_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=None
)


# ============================================================
# FEATURE NAMES
# ============================================================

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",

    "num_subdomains",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_digits",
    "num_letters",
    "num_special_chars",

    "digit_ratio",
    "letter_ratio",

    "num_query_params",
    "path_depth",
    "num_percent_encoded",

    "has_ip_host",
    "has_https",
    "has_port",
    "has_userinfo",

    "hostname_entropy",
    "url_entropy",
]


# ============================================================
# HELPERS
# ============================================================

def shannon_entropy(text: str) -> float:
    """
    Shannon entropy của chuỗi.

    Trả 0.0 nếu chuỗi rỗng.
    """

    if not text:
        return 0.0

    counts = Counter(
        text
    )

    length = len(
        text
    )

    entropy = 0.0

    for count in counts.values():

        probability = (
            count
            / length
        )

        entropy -= (
            probability
            * log2(
                probability
            )
        )

    return float(
        entropy
    )


def safe_urlsplit(url: str):
    """
    Parse URL an toàn.

    Dataset handoff của nhóm đã normalize URL,
    nhưng helper này vẫn hỗ trợ URL thiếu scheme.
    """

    if url is None:
        return None

    try:

        if pd.isna(url):
            return None

    except Exception:
        pass

    url = str(
        url
    ).strip()

    if not url:
        return None

    # Nếu thiếu scheme thì thêm http tạm để parse hostname.
    if "://" not in url:

        parse_target = (
            "http://"
            + url
        )

    else:

        parse_target = url

    try:

        parsed = urlsplit(
            parse_target
        )

    except Exception:

        return None

    return parsed


def is_ip_address(
    hostname: str
) -> int:
    """
    Hostname có phải IPv4/IPv6 hay không.
    """

    if not hostname:
        return 0

    try:

        ipaddress.ip_address(
            hostname
        )

        return 1

    except ValueError:

        return 0


def count_subdomains(
    hostname: str
) -> int:
    """
    Đếm số label subdomain.

    Ví dụ:
        login.secure.example.com
        -> 2
    """

    if not hostname:
        return 0

    # IP không có subdomain theo nghĩa domain.
    if is_ip_address(
        hostname
    ):
        return 0

    ext = TLD_EXTRACT(
        hostname
    )

    subdomain = (
        ext.subdomain
        or ""
    )

    if not subdomain:
        return 0

    return len(
        [
            part
            for part in subdomain.split(".")
            if part
        ]
    )


def count_query_params(
    query: str
) -> int:
    """
    Đếm số query parameter mà không decode query.

    Ví dụ:
        a=1&b=2
        -> 2
    """

    if not query:
        return 0

    parts = [
        part
        for part in query.split("&")
        if part != ""
    ]

    return len(
        parts
    )


def count_path_depth(
    path: str
) -> int:
    """
    Đếm số segment path.

    Ví dụ:
        /login/account/check
        -> 3
    """

    if not path:
        return 0

    parts = [
        part
        for part in path.split("/")
        if part
    ]

    return len(
        parts
    )


def count_percent_encoded(
    url: str
) -> int:
    """
    Đếm số pattern percent encoding dạng %XX.

    Ví dụ:
        %20
        %2F
    """

    if not url:
        return 0

    return len(
        re.findall(
            r"%[0-9A-Fa-f]{2}",
            url,
        )
    )


# ============================================================
# STRUCTURAL FEATURE EXTRACTOR
# ============================================================

def extract_structural_features(
    url: str
) -> dict:
    """
    Trích structural features cho một URL.

    Chỉ dựa trên cấu trúc URL,
    không dùng label và không truy cập URL.
    """

    if url is None:

        url = ""

    try:

        if pd.isna(url):
            url = ""

    except Exception:
        pass

    url = str(
        url
    ).strip()

    parsed = safe_urlsplit(
        url
    )

    if parsed is None:

        parsed_hostname = ""
        parsed_path = ""
        parsed_query = ""
        parsed_fragment = ""
        parsed_scheme = ""
        parsed_netloc = ""

    else:

        parsed_hostname = (
            parsed.hostname
            or ""
        )

        parsed_path = (
            parsed.path
            or ""
        )

        parsed_query = (
            parsed.query
            or ""
        )

        parsed_fragment = (
            parsed.fragment
            or ""
        )

        parsed_scheme = (
            parsed.scheme
            or ""
        )

        parsed_netloc = (
            parsed.netloc
            or ""
        )

    hostname = (
        parsed_hostname
        .lower()
        .strip(".")
    )

    # ========================================================
    # BASIC LENGTHS
    # ========================================================

    url_length = len(
        url
    )

    hostname_length = len(
        hostname
    )

    path_length = len(
        parsed_path
    )

    query_length = len(
        parsed_query
    )

    fragment_length = len(
        parsed_fragment
    )

    # ========================================================
    # CHARACTER COUNTS
    # ========================================================

    num_dots = url.count(
        "."
    )

    num_hyphens = url.count(
        "-"
    )

    num_underscores = url.count(
        "_"
    )

    num_slashes = url.count(
        "/"
    )

    num_digits = sum(
        char.isdigit()
        for char in url
    )

    num_letters = sum(
        char.isalpha()
        for char in url
    )

    num_special_chars = sum(
        not char.isalnum()
        for char in url
    )

    # ========================================================
    # RATIOS
    # ========================================================

    if url_length > 0:

        digit_ratio = (
            num_digits
            / url_length
        )

        letter_ratio = (
            num_letters
            / url_length
        )

    else:

        digit_ratio = 0.0
        letter_ratio = 0.0

    # ========================================================
    # STRUCTURAL COUNTS
    # ========================================================

    num_subdomains = count_subdomains(
        hostname
    )

    num_query_params = count_query_params(
        parsed_query
    )

    path_depth = count_path_depth(
        parsed_path
    )

    num_percent_encoded = count_percent_encoded(
        url
    )

    # ========================================================
    # BOOLEAN FEATURES
    # ========================================================

    has_ip_host = is_ip_address(
        hostname
    )

    has_https = int(
        parsed_scheme.lower()
        == "https"
    )

    has_userinfo = int(
        "@"
        in parsed_netloc
    )

    # parsed.port có thể raise ValueError
    try:

        has_port = int(
            parsed is not None
            and parsed.port is not None
        )

    except ValueError:

        has_port = 0

    # ========================================================
    # ENTROPY
    # ========================================================

    hostname_entropy = shannon_entropy(
        hostname
    )

    url_entropy = shannon_entropy(
        url
    )

    # ========================================================
    # RESULT
    # ========================================================

    features = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "fragment_length": fragment_length,

        "num_subdomains": num_subdomains,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_digits": num_digits,
        "num_letters": num_letters,
        "num_special_chars": num_special_chars,

        "digit_ratio": digit_ratio,
        "letter_ratio": letter_ratio,

        "num_query_params": num_query_params,
        "path_depth": path_depth,
        "num_percent_encoded": num_percent_encoded,

        "has_ip_host": has_ip_host,
        "has_https": has_https,
        "has_port": has_port,
        "has_userinfo": has_userinfo,

        "hostname_entropy": hostname_entropy,
        "url_entropy": url_entropy,
    }

    # Đảm bảo thứ tự và tên feature ổn định.
    return {
        name: features[
            name
        ]
        for name in FEATURE_NAMES
    }


# ============================================================
# BATCH EXTRACTION
# ============================================================

def extract_structural_features_dataframe(
    urls
) -> pd.DataFrame:
    """
    Trích structural features cho nhiều URL.

    Input:
        iterable URL strings

    Output:
        DataFrame chỉ chứa feature columns.
    """

    rows = []

    for url in urls:

        rows.append(
            extract_structural_features(
                url
            )
        )

    return pd.DataFrame(
        rows,
        columns=FEATURE_NAMES,
    )


# ============================================================
# SELF TEST
# ============================================================

def run_self_test():

    print(
        "========================================"
    )

    print(
        "DEFENSE D2 STRUCTURAL FEATURES SELF TEST"
    )

    print(
        "========================================"
    )

    test_urls = [
        (
            "https://www.example.com/"
            "login/account?user=123&lang=en"
        ),

        (
            "http://192.168.1.10:8080/"
            "verify/index.php?id=12345"
        ),

        (
            "https://secure.login.example.co.uk/"
            "a/b/c"
        ),

        (
            "https://example.com/"
            "download/%2Ftest%20file"
        ),

        (
            "http://user:pass@example.com/"
            "portal"
        ),
    ]

    df = (
        extract_structural_features_dataframe(
            test_urls
        )
    )

    print(
        "\nFEATURE NAMES:"
    )

    print(
        FEATURE_NAMES
    )

    print(
        "\nFEATURE COUNT:",
        len(
            FEATURE_NAMES
        )
    )

    print(
        "\nRESULT:"
    )

    print(
        df.to_string(
            index=False
        )
    )

    # ========================================================
    # ASSERTIONS
    # ========================================================

    assert list(
        df.columns
    ) == FEATURE_NAMES

    assert len(
        df
    ) == len(
        test_urls
    )

    assert (
        df.isna()
        .sum()
        .sum()
        == 0
    )

    # URL 1 là HTTPS
    assert (
        df.iloc[
            0
        ][
            "has_https"
        ]
        == 1
    )

    # URL 2 dùng IP
    assert (
        df.iloc[
            1
        ][
            "has_ip_host"
        ]
        == 1
    )

    # URL 2 có explicit port 8080
    assert (
        df.iloc[
            1
        ][
            "has_port"
        ]
        == 1
    )

    # secure.login.example.co.uk
    # có 2 subdomain: secure + login
    assert (
        df.iloc[
            2
        ][
            "num_subdomains"
        ]
        == 2
    )

    # URL 4 có %2F và %20
    assert (
        df.iloc[
            3
        ][
            "num_percent_encoded"
        ]
        == 2
    )

    # URL 5 có userinfo
    assert (
        df.iloc[
            4
        ][
            "has_userinfo"
        ]
        == 1
    )

    # Tất cả entropy không âm
    assert (
        df[
            "hostname_entropy"
        ]
        >= 0
    ).all()

    assert (
        df[
            "url_entropy"
        ]
        >= 0
    ).all()

    print(
        "\n========================================"
    )

    print(
        "STRUCTURAL FEATURES SELF TEST PASSED"
    )

    print(
        "========================================"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    run_self_test()