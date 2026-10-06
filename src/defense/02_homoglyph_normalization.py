import unicodedata


# ============================================================
# CONSERVATIVE HOMOGLYPH MAP
# ============================================================

# Chỉ map những ký tự Cyrillic / Greek rất dễ bị nhầm
# với ký tự Latin ASCII.
#
# Không map quá rộng để tránh làm sai các domain Unicode
# hợp lệ.

HOMOGLYPH_MAP = {

    # --------------------------------------------------------
    # CYRILLIC LOWERCASE
    # --------------------------------------------------------

    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ј": "j",


    # --------------------------------------------------------
    # CYRILLIC UPPERCASE
    # --------------------------------------------------------

    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",


    # --------------------------------------------------------
    # GREEK LOWERCASE
    # --------------------------------------------------------

    "ο": "o",
    "ρ": "p",
    "ν": "v",


    # --------------------------------------------------------
    # GREEK UPPERCASE
    # --------------------------------------------------------

    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Χ": "X",
}


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_homoglyph_text(text):
    """
    Thay các Unicode homoglyph đã biết bằng
    ký tự Latin tương ứng.

    Ví dụ:

        pаypal.com

    trong đó "а" là Cyrillic

        ->

        paypal.com
    """

    if text is None:
        return None

    text = str(text)

    # Unicode canonical normalization
    text = unicodedata.normalize(
        "NFKC",
        text
    )

    result = []

    for char in text:

        mapped = HOMOGLYPH_MAP.get(
            char,
            char
        )

        result.append(
            mapped
        )

    return "".join(
        result
    )


# ============================================================
# HOST NORMALIZATION
# ============================================================

def normalize_homoglyph_host(host):
    """
    Normalize homoglyph trong hostname.

    Sau khi map, hostname được lowercase.
    """

    if not host:
        return None

    host = normalize_homoglyph_text(
        host
    )

    if host is None:
        return None

    return host.lower()


# ============================================================
# DETECTION
# ============================================================

def contains_known_homoglyph(text):
    """
    Kiểm tra text có chứa ít nhất một homoglyph
    nằm trong HOMOGLYPH_MAP hay không.
    """

    if text is None:
        return False

    return any(
        char in HOMOGLYPH_MAP
        for char in str(text)
    )


# ============================================================
# COUNT
# ============================================================

def count_known_homoglyphs(text):
    """
    Đếm số ký tự homoglyph đã biết trong text.
    """

    if text is None:
        return 0

    return sum(
        1
        for char in str(text)
        if char in HOMOGLYPH_MAP
    )


# ============================================================
# SELF TEST
# ============================================================

if __name__ == "__main__":

    print(
        "=== HOMOGLYPH NORMALIZATION SELF TEST ==="
    )


    tests = [

        # 1. Cyrillic а
        (
            "pаypal.com",
            "paypal.com"
        ),

        # 2. Cyrillic о
        (
            "gооgle.com",
            "google.com"
        ),

        # 3. Cyrillic р
        (
            "рaypal.com",
            "paypal.com"
        ),

        # 4. Cyrillic с
        (
            "miсrosoft.com",
            "microsoft.com"
        ),

        # 5. Cyrillic х
        (
            "boх.com",
            "box.com"
        ),

        # 6. Cyrillic у
        (
            "paуpal.com",
            "paypal.com"
        ),

        # 7. Cyrillic і
        (
            "mіcrosoft.com",
            "microsoft.com"
        ),

        # 8. Multiple Cyrillic homoglyphs
        (
            "раураl.com",
            "paypal.com"
        ),

        # 9. Greek ο
        (
            "gοogle.com",
            "google.com"
        ),

        # 10. Normal ASCII unchanged
        (
            "example.com",
            "example.com"
        ),

        # 11. Unicode thật không nằm trong map
        (
            "bücher.example",
            "bücher.example"
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

        result = normalize_homoglyph_host(
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
        "HOMOGLYPH TEST SUMMARY"
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
        "Some homoglyph tests failed."
    )


    print(
        "\nHOMOGLYPH SELF TEST PASSED"
    )