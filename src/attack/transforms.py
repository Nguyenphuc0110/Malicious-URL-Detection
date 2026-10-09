import random
import re
import urllib.parse
import ipaddress

import idna
import tldextract


# ============================================================
# TLD EXTRACT
# ============================================================

# Dùng offline để kết quả nhất quán với pipeline dữ liệu.
TLD_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=None
)


# ============================================================
# HELPERS
# ============================================================

def _parse_url(url: str):
    """
    Parse URL.

    Dataset handoff của nhóm đã normalize và có scheme,
    nên attack pipeline yêu cầu URL có scheme + netloc.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None

    if not parsed.scheme or not parsed.netloc:
        return None

    return parsed


def extract_registered_domain(url: str) -> str:
    """
    Trả registered domain theo Public Suffix List.

    Ví dụ:
        https://abc.example.co.uk/a
        -> example.co.uk

    Nếu hostname là IP:
        -> chính IP.
    """
    parsed = _parse_url(url)

    if parsed is None:
        return ""

    host = parsed.hostname

    if not host:
        return ""

    host = host.lower().strip(".")

    # IP
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    ext = TLD_EXTRACT(host)

    registered = ext.top_domain_under_public_suffix

    if registered:
        return registered.lower()

    return host


def _replace_hostname(
    parsed: urllib.parse.ParseResult,
    new_hostname: str,
) -> str:
    """
    Thay hostname nhưng giữ:
        username
        password
        port
        path/query/fragment
    """
    userinfo = ""

    if parsed.username is not None:
        userinfo = parsed.username

        if parsed.password is not None:
            userinfo += ":" + parsed.password

        userinfo += "@"

    port = ""

    try:
        if parsed.port is not None:
            port = f":{parsed.port}"
    except ValueError:
        return urllib.parse.urlunparse(parsed)

    new_netloc = (
        userinfo
        + new_hostname
        + port
    )

    return urllib.parse.urlunparse(
        parsed._replace(
            netloc=new_netloc
        )
    )


def _replace_registered_domain(
    url: str,
    new_registered_domain: str,
) -> str:
    """
    Thay registered domain nhưng giữ subdomain cũ.

    Ví dụ:
        login.abc.com
        abc.com -> a-bc.com

        => login.a-bc.com
    """
    parsed = _parse_url(url)

    if parsed is None:
        return url

    host = parsed.hostname

    if not host:
        return url

    host = host.lower().strip(".")

    current_registered = extract_registered_domain(
        url
    )

    if not current_registered:
        return url

    if host == current_registered:
        new_host = new_registered_domain

    elif host.endswith(
        "." + current_registered
    ):
        prefix = host[
            : -len(current_registered)
        ]

        new_host = (
            prefix
            + new_registered_domain
        )

    else:
        return url

    return _replace_hostname(
        parsed,
        new_host,
    )


# ============================================================
# T1
# ============================================================

def T1_add_param_or_path(
    url: str
) -> str:
    """
    T1:
    Thêm query parameter trông bình thường.

    Registered domain không đổi.
    """
    parsed = _parse_url(url)

    if parsed is None:
        return url

    params = [
        "utm_source=mail",
        "utm_medium=email",
        "ref=home",
        "lang=en",
        "session_id=892374",
        "v=1.2.4",
    ]

    new_param = random.choice(
        params
    )

    if parsed.query:
        new_query = (
            parsed.query
            + "&"
            + new_param
        )
    else:
        new_query = new_param

    return urllib.parse.urlunparse(
        parsed._replace(
            query=new_query
        )
    )


# ============================================================
# T2
# ============================================================

def T2_add_subdomain(
    url: str
) -> str:
    """
    T2:
    Thêm subdomain.

    Registered domain bắt buộc giữ nguyên.
    """
    parsed = _parse_url(url)

    if parsed is None:
        return url

    host = parsed.hostname

    if not host:
        return url

    # Không áp dụng với IP.
    try:
        ipaddress.ip_address(host)
        return url
    except ValueError:
        pass

    subdomains = [
        "account",
        "support",
        "verify",
        "secure",
        "login",
        "auth",
        "update",
    ]

    new_sub = random.choice(
        subdomains
    )

    new_host = (
        new_sub
        + "."
        + host
    )

    return _replace_hostname(
        parsed,
        new_host,
    )


# ============================================================
# T3
# ============================================================

def T3_replace_keywords(
    url: str
) -> str:
    """
    T3:
    Thay keyword đáng ngờ CHỈ trong path/query.

    Không bao giờ sửa hostname.

    Đây là điểm quan trọng để T3 giữ nguyên
    registered domain theo yêu cầu T1-T4.
    """
    parsed = _parse_url(url)

    if parsed is None:
        return url

    suspicious_map = {
        "login": "member",
        "verify": "check",
        "secure": "portal",
        "account": "user",
        "update": "info",
        "bank": "service",
    }

    new_path = parsed.path
    new_query = parsed.query

    changed = False

    for word, replacement in (
        suspicious_map.items()
    ):
        replaced_path = re.sub(
            re.escape(word),
            replacement,
            new_path,
            flags=re.IGNORECASE,
        )

        replaced_query = re.sub(
            re.escape(word),
            replacement,
            new_query,
            flags=re.IGNORECASE,
        )

        if replaced_path != new_path:
            changed = True

        if replaced_query != new_query:
            changed = True

        new_path = replaced_path
        new_query = replaced_query

    # Nếu path/query không chứa keyword,
    # thêm một path trung tính.
    if not changed:
        base = parsed.path.rstrip("/")

        if not base:
            base = ""

        new_path = (
            base
            + "/index"
        )

    return urllib.parse.urlunparse(
        parsed._replace(
            path=new_path,
            query=new_query,
        )
    )


# ============================================================
# T4
# ============================================================

def T4_http_to_https(
    url: str
) -> str:
    """
    T4:
    http -> https.

    Nếu đã https thì trả nguyên URL.
    Validator sẽ reject no-op.
    """
    parsed = _parse_url(url)

    if parsed is None:
        return url

    if parsed.scheme.lower() != "http":
        return url

    return urllib.parse.urlunparse(
        parsed._replace(
            scheme="https"
        )
    )


# ============================================================
# T5
# ============================================================

def T5_insert_hyphen(
    url: str
) -> str:
    """
    T5:
    Chèn dấu '-' vào label domain chính.

    Ví dụ:
        example.com
        -> exa-mple.com
    """
    parsed = _parse_url(url)

    if parsed is None:
        return url

    host = parsed.hostname

    if not host:
        return url

    # Không sửa IP.
    try:
        ipaddress.ip_address(host)
        return url
    except ValueError:
        pass

    ext = TLD_EXTRACT(host)

    domain_name = ext.domain
    suffix = ext.suffix

    if (
        not domain_name
        or not suffix
        or len(domain_name) <= 3
    ):
        return url

    idx = len(domain_name) // 2

    new_domain_name = (
        domain_name[:idx]
        + "-"
        + domain_name[idx:]
    )

    new_registered = (
        new_domain_name
        + "."
        + suffix
    )

    return _replace_registered_domain(
        url,
        new_registered,
    )


# ============================================================
# T6
# ============================================================

def T6_typosquatting(
    url: str
) -> str:
    """
    T6:
    Thay một ký tự trong domain chính.
    """
    parsed = _parse_url(url)

    if parsed is None:
        return url

    host = parsed.hostname

    if not host:
        return url

    try:
        ipaddress.ip_address(host)
        return url
    except ValueError:
        pass

    ext = TLD_EXTRACT(host)

    domain_name = ext.domain
    suffix = ext.suffix

    if not domain_name or not suffix:
        return url

    typo_map = {
        "a": "4",
        "e": "3",
        "i": "1",
        "o": "0",
        "s": "5",
        "l": "1",
    }

    chars = list(
        domain_name
    )

    changed = False

    for i, char in enumerate(
        chars
    ):
        lower_char = char.lower()

        if lower_char in typo_map:
            chars[i] = typo_map[
                lower_char
            ]

            changed = True
            break

    # Fallback nếu không có ký tự trong map.
    if (
        not changed
        and len(chars) > 2
    ):
        chars.insert(
            1,
            chars[0],
        )

        changed = True

    if not changed:
        return url

    new_domain_name = "".join(
        chars
    )

    new_registered = (
        new_domain_name
        + "."
        + suffix
    )

    return _replace_registered_domain(
        url,
        new_registered,
    )


# ============================================================
# T7
# ============================================================

def T7_homoglyph_punycode(
    url: str
) -> str:
    """
    T7:
    Thay một ký tự Latin bằng homoglyph Cyrillic
    rồi encode registered domain sang IDNA/Punycode.
    """
    parsed = _parse_url(url)

    if parsed is None:
        return url

    host = parsed.hostname

    if not host:
        return url

    try:
        ipaddress.ip_address(host)
        return url
    except ValueError:
        pass

    ext = TLD_EXTRACT(host)

    domain_name = ext.domain
    suffix = ext.suffix

    if not domain_name or not suffix:
        return url

    homoglyphs = {
        "a": "\u0430",  # Cyrillic a
        "e": "\u0435",  # Cyrillic e
        "o": "\u043e",  # Cyrillic o
        "p": "\u0440",  # Cyrillic p
    }

    chars = list(
        domain_name
    )

    changed = False

    for i, char in enumerate(
        chars
    ):
        lower_char = char.lower()

        if lower_char in homoglyphs:
            chars[i] = homoglyphs[
                lower_char
            ]

            changed = True
            break

    if not changed:
        return url

    unicode_registered = (
        "".join(chars)
        + "."
        + suffix
    )

    try:
        punycode_registered = (
            idna.encode(
                unicode_registered
            )
            .decode("ascii")
        )

    except Exception:
        return url

    return _replace_registered_domain(
        url,
        punycode_registered,
    )


# ============================================================
# TRANSFORM REGISTRY
# ============================================================

TRANSFORM_FUNCTIONS = {
    "T1": T1_add_param_or_path,
    "T2": T2_add_subdomain,
    "T3": T3_replace_keywords,
    "T4": T4_http_to_https,
    "T5": T5_insert_hyphen,
    "T6": T6_typosquatting,
    "T7": T7_homoglyph_punycode,
}


# ============================================================
# VALIDATION
# ============================================================

def validate_transform(
    orig_url: str,
    trans_url: str,
    transform_type: str,
    benign_domains_set: set,
) -> bool:
    """
    Kiểm tra transform hợp lệ.

    Quy tắc:
      1. URL phải thực sự thay đổi.
      2. <= 2048 ký tự.
      3. Parse được, có scheme + netloc.
      4. Registered domain hợp lệ.
      5. T1-T4 phải giữ nguyên registered domain.
      6. Domain mới của T5-T7 không được trùng
         benign/Tranco set.
    """

    # Transform phải thực sự thay đổi URL.
    if trans_url == orig_url:
        return False

    if not isinstance(
        trans_url,
        str,
    ):
        return False

    if len(trans_url) > 2048:
        return False

    parsed_orig = _parse_url(
        orig_url
    )

    parsed_trans = _parse_url(
        trans_url
    )

    if (
        parsed_orig is None
        or parsed_trans is None
    ):
        return False

    orig_domain = extract_registered_domain(
        orig_url
    )

    trans_domain = extract_registered_domain(
        trans_url
    )

    if (
        not orig_domain
        or not trans_domain
    ):
        return False

    # T1-T4 bắt buộc giữ registered domain.
    if transform_type in {
        "T1",
        "T2",
        "T3",
        "T4",
    }:
        if (
            orig_domain.lower()
            != trans_domain.lower()
        ):
            return False

    benign_normalized = {
        str(domain).lower().strip()
        for domain in benign_domains_set
        if domain
    }

    # Nếu domain mới khác domain gốc thì
    # không được "mượn" benign domain.
    if (
        trans_domain.lower()
        != orig_domain.lower()
        and trans_domain.lower()
        in benign_normalized
    ):
        return False

    return True


# ============================================================
# SELF TEST
# ============================================================

if __name__ == "__main__":

    benign_domains = {
        "google.com",
        "facebook.com",
        "paypal.com",
        "tranco-list.eu",
    }

    sample_urls = [
        "http://secure-login-paypal-test.com/verify/account",
        "http://update-bank-info.net/login.php",
        "http://verify-user-portal.org/secure",
    ]

    print(
        "=== TRANSFORM SELF TEST ==="
    )

    for code, fn in (
        TRANSFORM_FUNCTIONS.items()
    ):

        print(
            f"\n--- {code} ---"
        )

        valid_count = 0

        for original in sample_urls:

            transformed = fn(
                original
            )

            valid = validate_transform(
                original,
                transformed,
                code,
                benign_domains,
            )

            print(
                "ORIG :",
                original
            )

            print(
                "ADV  :",
                transformed
            )

            print(
                "VALID:",
                valid
            )

            if valid:
                valid_count += 1

        print(
            f"{code}: "
            f"{valid_count}/"
            f"{len(sample_urls)} valid"
        )