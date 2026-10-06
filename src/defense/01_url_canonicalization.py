from urllib.parse import (
    urlsplit,
    urlunsplit,
)

import re
import unicodedata

import idna


# ============================================================
# CONFIG
# ============================================================

# Các tracking parameter có độ chắc chắn cao.
#
# Không xóa "ref" / "referrer" vì chúng có thể là
# parameter chức năng của website.
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
    Chuẩn hóa hostname.

    Thực hiện:
        - strip whitespace
        - lowercase
        - Unicode NFKC normalization
        - bỏ dấu chấm cuối domain
        - decode punycode / IDN nếu có thể

    Ví dụ:

        EXAMPLE.COM
            ->
        example.com

        example.com.
            ->
        example.com

        xn--bcher-kva.example
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

    # Decode Punycode / IDN
    try:

        host = idna.decode(
            host
        )

    except Exception:

        # Nếu không decode được thì giữ nguyên hostname
        pass

    return host


# ============================================================
# QUERY NORMALIZATION
# ============================================================

def clean_query(query):
    """
    Loại tracking parameters nhưng cố gắng giữ nguyên
    representation của query còn lại.

    QUAN TRỌNG:

    Không dùng:
        parse_qsl()
        urlencode()

    Vì các hàm trên có thể biến đổi URL:

        node/514
            ->
        node%2F514

        %20
            ->
        +

        ?flag
            ->
        ?flag=

    Hàm này chỉ xác định key của từng raw query segment
    rồi loại segment nếu đó là tracking parameter.

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

        # ----------------------------------------
        # Empty query segment
        # ----------------------------------------
        #
        # Giữ lại để không tự ý sửa lexical form:
        #
        # a=1&&b=2
        # a=1&
        #
        # Những trường hợp này có thể có giá trị
        # đối với lexical feature của model.

        if part == "":

            cleaned.append(
                part
            )

            continue


        # ----------------------------------------
        # GET PARAMETER KEY
        # ----------------------------------------

        if "=" in part:

            key = part.split(
                "=",
                1
            )[0]

        else:

            # dạng:
            #
            # ?flag
            #
            # Không tự đổi thành flag=
            key = part


        key_lower = (
            key
            .lower()
            .strip()
        )


        # ----------------------------------------
        # REMOVE TRACKING PARAM
        # ----------------------------------------

        if is_tracking_param(
            key_lower
        ):
            continue


        # ----------------------------------------
        # KEEP RAW PARAMETER
        # ----------------------------------------

        cleaned.append(
            part
        )


    # Nếu tất cả parameter thật đều bị loại và
    # chỉ còn separator rỗng thì bỏ query luôn.
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

    Thực hiện:

    1. strip whitespace
    2. đổi &amp; -> &
    3. thêm http:// nếu thiếu scheme
    4. lowercase scheme
    5. lowercase + normalize hostname
    6. decode punycode
    7. bỏ default ports:
           HTTP  -> 80
           HTTPS -> 443
           FTP   -> 21
    8. giữ nguyên path
    9. loại tracking parameters
    10. bỏ fragment
    11. giữ nguyên percent encoding
    12. hỗ trợ HTTP / HTTPS / FTP

    Không truy cập URL và không gửi network request.

    Return:
        canonical URL

    Nếu URL không thể xử lý:
        None
    """

    # ========================================================
    # NULL / EMPTY CHECK
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

    # Chỉ decode "&amp;".
    #
    # KHÔNG dùng:
    #
    # html.unescape(url)
    #
    # vì ví dụ:
    #
    # &region1
    #
    # có thể bị hiểu sai thành:
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

    # Dataset có ít nhất một phishing URL dùng FTP.
    #
    # Không đổi ftp -> http vì sẽ thay đổi URL gốc.
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
        #
        # http://example.com:abc/
        #
        # port không hợp lệ.
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

    # Giữ lại userinfo nếu URL có dạng:
    #
    # http://user:password@example.com/
    #
    # Vì đây cũng có thể là lexical information quan trọng.

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
    # Khi rebuild URL phải thêm lại []:
    #
    # 2001:db8::1
    #
    # ->
    #
    # [2001:db8::1]

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
    #
    # - decode percent encoding
    # - encode lại
    # - lowercase path
    # - tự thêm "/"
    #
    # Vì những thay đổi này có thể làm mất lexical features.

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

    # Fragment không được gửi tới HTTP server.
    #
    # D1 canonicalization bỏ fragment.

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
        # Facebook tracking
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
        # Non-default port must remain
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
        # Root URL: do NOT add /
        # ====================================================

        (
            "https://example.com",

            "https://example.com"
        ),


        # ====================================================
        # TEST 13
        # Trailing dot hostname
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
        # Preserve slash inside query value
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
        # Preserve flag-style query parameter
        # ====================================================

        (
            "https://example.com/page?lca",

            "https://example.com/page?lca"
        ),


        # ====================================================
        # TEST 18
        # Remove UTM without re-encoding normal value
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