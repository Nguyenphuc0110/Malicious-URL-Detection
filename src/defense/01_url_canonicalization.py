from urllib.parse import (
    urlsplit,
    urlunsplit,
    parse_qsl,
    urlencode,
)

import html
import unicodedata

import idna


# ============================================================
# CONFIG
# ============================================================

# Các query parameter chủ yếu dùng cho tracking
TRACKING_PARAMS = {
    "gclid",
    "fbclid",
    "msclkid",
    "dclid",
    "yclid",
    "mc_cid",
    "mc_eid",
    "ref",
    "referrer",
}


# ============================================================
# TRACKING PARAM CHECK
# ============================================================

def is_tracking_param(key):
    """
    Kiểm tra query parameter có phải tracking parameter không.
    """

    key = str(key).lower().strip()

    # Tất cả utm_*
    if key.startswith("utm_"):
        return True

    return key in TRACKING_PARAMS


# ============================================================
# HOST NORMALIZATION
# ============================================================

def normalize_host(host):
    """
    Chuẩn hóa hostname:

    - lowercase
    - Unicode NFKC normalization
    - bỏ dấu chấm cuối domain
    - decode punycode/IDN nếu có thể

    Ví dụ:
        XN--BCHER-KVA.EXAMPLE
        ->
        bücher.example
    """

    if not host:
        return None

    host = str(host).strip().lower()

    # Unicode normalization
    host = unicodedata.normalize(
        "NFKC",
        host
    )

    # example.com. -> example.com
    host = host.rstrip(".")

    try:
        host = idna.decode(host)

    except Exception:
        # Nếu không decode được thì giữ host ban đầu
        pass

    return host


# ============================================================
# QUERY NORMALIZATION
# ============================================================

def clean_query(query):
    """
    Loại tracking parameters nhưng giữ các query parameter
    có chức năng thật.

    Ví dụ:

    ?utm_source=email&id=123
        ->
    ?id=123
    """

    if not query:
        return ""

    try:

        pairs = parse_qsl(
            query,
            keep_blank_values=True
        )

    except Exception:
        return query

    cleaned = []

    for key, value in pairs:

        if is_tracking_param(key):
            continue

        cleaned.append(
            (key, value)
        )

    return urlencode(
        cleaned,
        doseq=True
    )


# ============================================================
# MAIN CANONICALIZATION FUNCTION
# ============================================================

def canonicalize_url(url):
    """
    Defense D1: URL canonicalization.

    Các bước:

    1. strip whitespace
    2. HTML entity decode
       &amp; -> &
    3. thêm scheme nếu URL thiếu
    4. lowercase scheme
    5. lowercase + normalize hostname
    6. decode punycode
    7. bỏ default port :80 / :443
    8. bỏ tracking parameters
    9. bỏ fragment #...
    10. giữ nguyên path/percent encoding
    """

    # --------------------------------------------------------
    # NULL CHECK
    # --------------------------------------------------------

    if url is None:
        return None

    url = str(url).strip()

    if not url:
        return None


    # --------------------------------------------------------
    # HTML ENTITY
    # --------------------------------------------------------

    # docs.google.com/...&amp;id=...
    # ->
    # docs.google.com/...&id=...

    url = html.unescape(url)


    # --------------------------------------------------------
    # ADD SCHEME
    # --------------------------------------------------------

    if "://" not in url:

        url = (
            "http://"
            + url
        )


    # --------------------------------------------------------
    # PARSE URL
    # --------------------------------------------------------

    try:

        parsed = urlsplit(url)

    except Exception:

        return None


    # --------------------------------------------------------
    # SCHEME
    # --------------------------------------------------------

    scheme = (
        parsed.scheme
        .lower()
        .strip()
    )

    if scheme not in (
        "http",
        "https"
    ):
        return None


    # --------------------------------------------------------
    # HOSTNAME
    # --------------------------------------------------------

    host = normalize_host(
        parsed.hostname
    )

    if not host:
        return None


    # --------------------------------------------------------
    # PORT
    # --------------------------------------------------------

    try:

        port = parsed.port

    except ValueError:

        # invalid port
        return None


    # HTTP default port
    if (
        scheme == "http"
        and port == 80
    ):

        port = None


    # HTTPS default port
    if (
        scheme == "https"
        and port == 443
    ):

        port = None


    # --------------------------------------------------------
    # REBUILD NETLOC
    # --------------------------------------------------------

    if port is None:

        netloc = host

    else:

        netloc = (
            f"{host}:{port}"
        )


    # --------------------------------------------------------
    # PATH
    # --------------------------------------------------------

    path = parsed.path

    if not path:
        path = "/"


    # QUAN TRỌNG:
    #
    # Không decode percent encoding trong path.
    #
    # Ví dụ:
    # %E3%81...
    #
    # giữ nguyên để không vô tình thay đổi semantics URL.


    # --------------------------------------------------------
    # QUERY
    # --------------------------------------------------------

    query = clean_query(
        parsed.query
    )


    # --------------------------------------------------------
    # FRAGMENT
    # --------------------------------------------------------

    # Fragment không gửi tới server nên bỏ
    fragment = ""


    # --------------------------------------------------------
    # REBUILD FINAL URL
    # --------------------------------------------------------

    canonical = urlunsplit(
        (
            scheme,
            netloc,
            path,
            query,
            fragment,
        )
    )

    return canonical


# ============================================================
# SELF TEST
# ============================================================

if __name__ == "__main__":

    print(
        "=== DEFENSE D1 SELF TEST ==="
    )


    tests = [

        # ----------------------------------------------------
        # 1. Lowercase host
        # ----------------------------------------------------

        (
            "HTTP://EXAMPLE.COM/Login",
            "http://example.com/Login"
        ),


        # ----------------------------------------------------
        # 2. UTM tracking
        # ----------------------------------------------------

        (
            "https://example.com/login?utm_source=email&id=123",
            "https://example.com/login?id=123"
        ),


        # ----------------------------------------------------
        # 3. Multiple tracking parameters
        # ----------------------------------------------------

        (
            "https://example.com/page?"
            "utm_source=email&"
            "utm_campaign=test&"
            "id=999",

            "https://example.com/page?id=999"
        ),


        # ----------------------------------------------------
        # 4. Facebook tracking
        # ----------------------------------------------------

        (
            "https://example.com/page?fbclid=ABC123&id=20",
            "https://example.com/page?id=20"
        ),


        # ----------------------------------------------------
        # 5. Fragment
        # ----------------------------------------------------

        (
            "https://example.com/page#section1",
            "https://example.com/page"
        ),


        # ----------------------------------------------------
        # 6. HTTP default port
        # ----------------------------------------------------

        (
            "http://example.com:80/login",
            "http://example.com/login"
        ),


        # ----------------------------------------------------
        # 7. HTTPS default port
        # ----------------------------------------------------

        (
            "https://example.com:443/login",
            "https://example.com/login"
        ),


        # ----------------------------------------------------
        # 8. Non-default port must remain
        # ----------------------------------------------------

        (
            "https://example.com:8443/login",
            "https://example.com:8443/login"
        ),


        # ----------------------------------------------------
        # 9. HTML entity
        # ----------------------------------------------------

        (
            "https://example.com/page?a=1&amp;b=2",
            "https://example.com/page?a=1&b=2"
        ),


        # ----------------------------------------------------
        # 10. Missing scheme
        # ----------------------------------------------------

        (
            "example.com/login",
            "http://example.com/login"
        ),


        # ----------------------------------------------------
        # 11. Tracking parameter only
        # ----------------------------------------------------

        (
            "https://example.com/page?utm_campaign=test",
            "https://example.com/page"
        ),


        # ----------------------------------------------------
        # 12. Root URL
        # ----------------------------------------------------

        (
            "https://example.com",
            "https://example.com/"
        ),


        # ----------------------------------------------------
        # 13. Trailing dot domain
        # ----------------------------------------------------

        (
            "https://example.com./login",
            "https://example.com/login"
        ),


        # ----------------------------------------------------
        # 14. Punycode / IDN
        # ----------------------------------------------------

        (
            "https://xn--bcher-kva.example/path",
            "https://bücher.example/path"
        ),
    ]


    passed = 0


    for number, (
        original,
        expected
    ) in enumerate(
        tests,
        start=1
    ):

        result = canonicalize_url(
            original
        )

        success = (
            result == expected
        )

        print(
            f"\n--- TEST {number} ---"
        )

        print(
            "Original :",
            original
        )

        print(
            "Result   :",
            result
        )

        print(
            "Expected :",
            expected
        )

        print(
            "PASS     :",
            success
        )


        if success:

            passed += 1


    # ========================================================
    # SUMMARY
    # ========================================================

    print(
        "\n===================================="
    )

    print(
        "DEFENSE D1 TEST SUMMARY"
    )

    print(
        "===================================="
    )

    print(
        f"Passed: {passed}/{len(tests)}"
    )


    assert passed == len(
        tests
    ), (
        "Some Defense D1 tests failed."
    )


    print(
        "\nDEFENSE D1 SELF TEST PASSED"
    )