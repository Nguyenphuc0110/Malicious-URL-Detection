from urllib.parse import (
    urlsplit,
    urlunsplit,
)

import importlib.util
from pathlib import Path
import re
import unicodedata

import idna


# ============================================================
# LOAD HOMOGLYPH MODULE
# ============================================================

# Vì tên file bắt đầu bằng "02_" nên không import theo cách
# thông thường. Load trực tiếp từ file cùng thư mục.

HOMOGLYPH_FILE = Path(__file__).with_name(
    "02_homoglyph_normalization.py"
)

_homoglyph_spec = importlib.util.spec_from_file_location(
    "homoglyph_normalization",
    HOMOGLYPH_FILE
)

if (
    _homoglyph_spec is None
    or _homoglyph_spec.loader is None
):
    raise ImportError(
        "Cannot load 02_homoglyph_normalization.py"
    )

_homoglyph_module = importlib.util.module_from_spec(
    _homoglyph_spec
)

_homoglyph_spec.loader.exec_module(
    _homoglyph_module
)

normalize_homoglyph_host = (
    _homoglyph_module.normalize_homoglyph_host
)


# ============================================================
# CONFIG
# ============================================================

# Chỉ loại các tracking parameter có độ chắc chắn cao.
#
# Không xóa:
#   ref
#   referrer
#
# vì chúng có thể là parameter chức năng thực sự.

TRACKING_PARAMS = {
    "gclid",
    "fbclid",
    "msclkid",
    "dclid",
    "yclid",
    "mc_cid",
    "mc_eid",
}


# ============================================================
# TRACKING PARAM CHECK
# ============================================================

def is_tracking_param(key):
    """
    Kiểm tra query parameter có phải tracking parameter không.

    Bao gồm:
        - utm_*
        - gclid
        - fbclid
        - msclkid
        - dclid
        - yclid
        - mc_cid
        - mc_eid
    """

    if key is None:
        return False

    key = str(key).lower().strip()

    # utm_source, utm_medium, utm_campaign, ...
    if key.startswith("utm_"):
        return True

    return key in TRACKING_PARAMS


# ============================================================
# HOST NORMALIZATION
# ============================================================

def normalize_host(host):
    """
    Chuẩn hóa hostname theo thứ tự:

        lowercase
            ↓
        Unicode NFKC
            ↓
        bỏ trailing dot
            ↓
        decode IDN / punycode
            ↓
        homoglyph normalization
            ↓
        lowercase lần cuối

    Ví dụ:

        EXAMPLE.COM
            ->
        example.com

        xn--bcher-kva.example
            ->
        bücher.example

        pаypal.com
          ↑ Cyrillic а
            ->
        paypal.com
    """

    if not host:
        return None

    host = str(host).strip().lower()

    # Unicode canonical normalization
    host = unicodedata.normalize(
        "NFKC",
        host
    )

    # example.com. -> example.com
    host = host.rstrip(".")

    # --------------------------------------------------------
    # IDN / PUNYCODE
    # --------------------------------------------------------

    try:

        host = idna.decode(
            host
        )

    except Exception:

        # Nếu không decode được thì giữ nguyên.
        pass


    # --------------------------------------------------------
    # HOMOGLYPH NORMALIZATION
    # --------------------------------------------------------

    host = normalize_homoglyph_host(
        host
    )

    if not host:
        return None

    return host.lower()


# ============================================================
# QUERY NORMALIZATION
# ============================================================

def clean_query(query):
    """
    Loại tracking parameters nhưng giữ nguyên representation
    của các query parameter còn lại.

    Không dùng:

        parse_qsl()
        urlencode()

    vì có thể làm thay đổi lexical representation:

        node/514
            ->
        node%2F514

        %20
            ->
        +

        ?flag
            ->
        ?flag=

    Ví dụ:

        utm_source=email&id=123
            ->
        id=123

        q=node/514&utm_campaign=test
            ->
        q=node/514
    """

    if not query:
        return ""

    parts = query.split("&")

    cleaned = []

    for part in parts:

        # ----------------------------------------------------
        # EMPTY SEGMENT
        # ----------------------------------------------------

        # Giữ segment rỗng để hạn chế thay đổi lexical
        # representation không cần thiết.
        #
        # Ví dụ:
        #   a=1&&b=2
        #   a=1&

        if part == "":

            cleaned.append(
                part
            )

            continue


        # ----------------------------------------------------
        # GET RAW KEY
        # ----------------------------------------------------

        if "=" in part:

            key = part.split(
                "=",
                1
            )[0]

        else:

            # Ví dụ:
            # ?flag
            key = part


        key_lower = (
            key
            .lower()
            .strip()
        )


        # ----------------------------------------------------
        # REMOVE TRACKING PARAM
        # ----------------------------------------------------

        if is_tracking_param(
            key_lower
        ):
            continue


        # ----------------------------------------------------
        # KEEP ORIGINAL RAW PARAMETER
        # ----------------------------------------------------

        cleaned.append(
            part
        )


    # Nếu sau khi bỏ tracking parameter chỉ còn các
    # segment rỗng thì bỏ toàn bộ query.
    if not any(
        part != ""
        for part in cleaned
    ):
        return ""


    return "&".join(
        cleaned
    )


# ============================================================
# MAIN DEFENSE D1
# ============================================================

def canonicalize_url(url):
    """
    Defense D1 - URL canonicalization.

    Các bước:

    1. strip whitespace
    2. đổi &amp; -> &
    3. thêm http:// nếu thiếu scheme
    4. lowercase scheme
    5. normalize hostname
    6. decode IDN / punycode
    7. normalize Unicode homoglyph
    8. bỏ default ports:
           HTTP  -> 80
           HTTPS -> 443
           FTP   -> 21
    9. giữ nguyên path
    10. loại tracking parameters
    11. bỏ fragment
    12. giữ nguyên percent encoding

    Hỗ trợ:
        http
        https
        ftp

    Hàm KHÔNG truy cập URL và KHÔNG gửi network request.

    Return:
        canonicalized URL

    Nếu URL không thể xử lý:
        None
    """

    # ========================================================
    # NULL / EMPTY
    # ========================================================

    if url is None:
        return None

    url = str(
        url
    ).strip()

    if not url:
        return None


    # ========================================================
    # HTML-ESCAPED AMPERSAND
    # ========================================================

    # Chỉ decode:
    #
    # &amp;
    #
    # Không dùng html.unescape() vì:
    #
    # &region1
    #
    # có thể bị hiểu thành:
    #
    # ®ion1

    url = re.sub(
        r"&amp;",
        "&",
        url,
        flags=re.IGNORECASE
    )


    # ========================================================
    # ADD SCHEME IF MISSING
    # ========================================================

    if "://" not in url:

        url = (
            "http://"
            + url
        )


    # ========================================================
    # PARSE URL
    # ========================================================

    try:

        parsed = urlsplit(
            url
        )

    except Exception:

        return None


    # ========================================================
    # SCHEME
    # ========================================================

    scheme = (
        parsed.scheme
        .lower()
        .strip()
    )

    if scheme not in (
        "http",
        "https",
        "ftp",
    ):
        return None


    # ========================================================
    # HOST
    # ========================================================

    host = normalize_host(
        parsed.hostname
    )

    if not host:
        return None


    # ========================================================
    # PORT
    # ========================================================

    try:

        port = parsed.port

    except ValueError:

        # Ví dụ:
        # http://example.com:abc/
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


    # FTP default port
    if (
        scheme == "ftp"
        and port == 21
    ):

        port = None


    # ========================================================
    # USER INFO
    # ========================================================

    # Giữ lại userinfo nếu tồn tại:
    #
    # http://user:password@example.com/
    #
    # vì đây có thể là lexical feature quan trọng.

    userinfo = ""

    if parsed.username is not None:

        userinfo = parsed.username

        if parsed.password is not None:

            userinfo += (
                ":"
                + parsed.password
            )

        userinfo += "@"


    # ========================================================
    # IPV6
    # ========================================================

    # urlsplit().hostname trả IPv6 không có [].
    #
    # Khi rebuild phải đưa [] trở lại.

    if (
        ":" in host
        and not (
            host.startswith("[")
            and host.endswith("]")
        )
    ):

        host_for_netloc = (
            f"[{host}]"
        )

    else:

        host_for_netloc = host


    # ========================================================
    # NETLOC
    # ========================================================

    if port is None:

        netloc = (
            userinfo
            + host_for_netloc
        )

    else:

        netloc = (
            userinfo
            + host_for_netloc
            + f":{port}"
        )


    # ========================================================
    # PATH
    # ========================================================

    # Giữ nguyên path.
    #
    # Không:
    # - lowercase path
    # - decode percent encoding
    # - encode lại path
    # - tự thêm "/"
    #
    # để tránh thay đổi lexical feature của model.

    path = parsed.path


    # ========================================================
    # QUERY
    # ========================================================

    query = clean_query(
        parsed.query
    )


    # ========================================================
    # FRAGMENT
    # ========================================================

    # Fragment không gửi tới HTTP server.
    fragment = ""


    # ========================================================
    # BUILD FINAL URL
    # ========================================================

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

        # ====================================================
        # TEST 1
        # Lowercase scheme + hostname
        # ====================================================

        (
            "HTTP://EXAMPLE.COM/Login",
            "http://example.com/Login"
        ),


        # ====================================================
        # TEST 2
        # Remove UTM
        # ====================================================

        (
            "https://example.com/login?"
            "utm_source=email&id=123",

            "https://example.com/login?id=123"
        ),


        # ====================================================
        # TEST 3
        # Multiple UTM
        # ====================================================

        (
            "https://example.com/page?"
            "utm_source=email&"
            "utm_campaign=test&"
            "id=999",

            "https://example.com/page?id=999"
        ),


        # ====================================================
        # TEST 4
        # FBCLID
        # ====================================================

        (
            "https://example.com/page?"
            "fbclid=ABC123&id=20",

            "https://example.com/page?id=20"
        ),


        # ====================================================
        # TEST 5
        # Remove fragment
        # ====================================================

        (
            "https://example.com/page#section1",
            "https://example.com/page"
        ),


        # ====================================================
        # TEST 6
        # Default HTTP port
        # ====================================================

        (
            "http://example.com:80/login",
            "http://example.com/login"
        ),


        # ====================================================
        # TEST 7
        # Default HTTPS port
        # ====================================================

        (
            "https://example.com:443/login",
            "https://example.com/login"
        ),


        # ====================================================
        # TEST 8
        # Non-default port remains
        # ====================================================

        (
            "https://example.com:8443/login",
            "https://example.com:8443/login"
        ),


        # ====================================================
        # TEST 9
        # &amp; -> &
        # ====================================================

        (
            "https://example.com/page?"
            "a=1&amp;b=2",

            "https://example.com/page?"
            "a=1&b=2"
        ),


        # ====================================================
        # TEST 10
        # Missing scheme
        # ====================================================

        (
            "example.com/login",
            "http://example.com/login"
        ),


        # ====================================================
        # TEST 11
        # Tracking parameter only
        # ====================================================

        (
            "https://example.com/page?"
            "utm_campaign=test",

            "https://example.com/page"
        ),


        # ====================================================
        # TEST 12
        # Root URL - do not add /
        # ====================================================

        (
            "https://example.com",
            "https://example.com"
        ),


        # ====================================================
        # TEST 13
        # Trailing dot
        # ====================================================

        (
            "https://example.com./login",
            "https://example.com/login"
        ),


        # ====================================================
        # TEST 14
        # Punycode / IDN
        # ====================================================

        (
            "https://xn--bcher-kva.example/path",
            "https://bücher.example/path"
        ),


        # ====================================================
        # TEST 15
        # Preserve slash in query
        # ====================================================

        (
            "http://example.com/page?"
            "q=node/514",

            "http://example.com/page?"
            "q=node/514"
        ),


        # ====================================================
        # TEST 16
        # Preserve %20
        # ====================================================

        (
            "http://example.com/page?"
            "artist=Loredana%20Groza",

            "http://example.com/page?"
            "artist=Loredana%20Groza"
        ),


        # ====================================================
        # TEST 17
        # Preserve flag-style query
        # ====================================================

        (
            "https://example.com/page?lca",
            "https://example.com/page?lca"
        ),


        # ====================================================
        # TEST 18
        # Remove UTM without re-encoding value
        # ====================================================

        (
            "https://example.com/page?"
            "q=node/514&"
            "utm_source=email",

            "https://example.com/page?"
            "q=node/514"
        ),


        # ====================================================
        # TEST 19
        # &region must NOT become ®ion
        # ====================================================

        (
            "http://example.com/page?"
            "town=Ciginj&region1=2859",

            "http://example.com/page?"
            "town=Ciginj&region1=2859"
        ),


        # ====================================================
        # TEST 20
        # FTP URL
        # ====================================================

        (
            "ftp://221.131.136.22/"
            "inloggen/abnamro.nl.htm",

            "ftp://221.131.136.22/"
            "inloggen/abnamro.nl.htm"
        ),


        # ====================================================
        # TEST 21
        # Cyrillic homoglyph:
        # "а" below is Cyrillic, not Latin a
        # ====================================================

        (
            "https://pаypal.com/login",
            "https://paypal.com/login"
        ),


        # ====================================================
        # TEST 22
        # Multiple Cyrillic homoglyphs:
        # both "о" below are Cyrillic
        # ====================================================

        (
            "https://gооgle.com/login",
            "https://google.com/login"
        ),

    ]


    # ========================================================
    # RUN TESTS
    # ========================================================

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
            result
            == expected
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


    assert (
        passed
        == len(tests)
    ), (
        "Some Defense D1 tests failed."
    )


    print(
        "\nDEFENSE D1 SELF TEST PASSED"
    )