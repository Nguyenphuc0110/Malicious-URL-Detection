import random

from src.attack.transforms import (
    TRANSFORM_FUNCTIONS,
    extract_registered_domain,
    validate_transform,
)

from src.attack.random_attack import (
    random_attack,
)

from src.attack.greedy_blackbox_attack import (
    greedy_blackbox_attack,
)


# ============================================================
# DUMMY MODEL
# ============================================================

def dummy_predict_proba(urls):
    """
    Dummy model chỉ dùng để test pipeline.

    KHÔNG dùng kết quả này cho E3/report chính thức.
    """

    url = urls[0].lower()

    score = 0.95

    if url.startswith("https://"):
        score -= 0.15

    if "utm_" in url:
        score -= 0.15

    if "member" in url:
        score -= 0.25

    if "portal" in url:
        score -= 0.15

    return max(
        0.01,
        min(
            0.99,
            score,
        ),
    )


# ============================================================
# MAIN TEST
# ============================================================

def main():

    random.seed(42)

    benign_domains = {
        "google.com",
        "facebook.com",
        "paypal.com",
        "tranco-list.eu",
    }

    test_url = (
        "http://secure-login-paypal-test.com/"
        "verify/account"
    )

    # ========================================================
    # 1. TEST T1-T7
    # ========================================================

    print(
        "================================"
    )

    print(
        "1. TEST T1-T7"
    )

    print(
        "================================"
    )

    original_domain = (
        extract_registered_domain(
            test_url
        )
    )

    for code, transform_fn in (
        TRANSFORM_FUNCTIONS.items()
    ):

        adv_url = transform_fn(
            test_url
        )

        valid = validate_transform(
            test_url,
            adv_url,
            code,
            benign_domains,
        )

        print(
            f"\n--- {code} ---"
        )

        print(
            "Original:",
            test_url
        )

        print(
            "Adv     :",
            adv_url
        )

        print(
            "Valid   :",
            valid
        )

        # T1-T4 bắt buộc giữ registered domain.
        if code in {
            "T1",
            "T2",
            "T3",
            "T4",
        }:

            adv_domain = (
                extract_registered_domain(
                    adv_url
                )
            )

            print(
                "Original domain:",
                original_domain
            )

            print(
                "Adv domain     :",
                adv_domain
            )

            assert (
                adv_domain
                == original_domain
            ), (
                f"{code} changed "
                "registered domain"
            )

        assert valid is True, (
            f"{code} failed validation"
        )

    print(
        "\nT1-T7 TEST PASSED"
    )

    # ========================================================
    # 2. RANDOM ATTACK
    # ========================================================

    print(
        "\n================================"
    )

    print(
        "2. RANDOM ATTACK"
    )

    print(
        "================================"
    )

    adv_url, applied = random_attack(
        url=test_url,
        k=5,
        benign_domains_set=benign_domains,
    )

    print(
        "Original:",
        test_url
    )

    print(
        "Adv:",
        adv_url
    )

    print(
        "Applied:",
        applied
    )

    # Không được dùng cùng một transform 2 lần.
    assert (
        len(applied)
        == len(
            set(applied)
        )
    )

    # Không được vượt budget.
    assert (
        len(applied)
        <= 5
    )

    # Nếu có transform thì URL phải đổi.
    if applied:

        assert (
            adv_url
            != test_url
        )

    print(
        "RANDOM ATTACK TEST PASSED"
    )

    # ========================================================
    # 3. GREEDY ATTACK
    # ========================================================

    print(
        "\n================================"
    )

    print(
        "3. GREEDY ATTACK"
    )

    print(
        "================================"
    )

    result = greedy_blackbox_attack(
        url=test_url,
        max_k=5,
        predict_proba_fn=dummy_predict_proba,
        threshold=0.5,
        benign_domains_set=benign_domains,
    )

    print(
        "Original URL:",
        result[
            "original_url"
        ]
    )

    print(
        "Adversarial URL:",
        result[
            "adv_url"
        ]
    )

    print(
        "Original score:",
        result[
            "original_score"
        ]
    )

    print(
        "Final score:",
        result[
            "final_score"
        ]
    )

    print(
        "Evaded:",
        result[
            "is_evaded"
        ]
    )

    print(
        "Total queries:",
        result[
            "total_queries"
        ]
    )

    print(
        "Applied transforms:",
        result[
            "applied_transforms"
        ]
    )

    print(
        "Score history:",
        result[
            "score_history"
        ]
    )

    # Greedy không được làm score tăng.
    assert (
        result[
            "final_score"
        ]
        <= result[
            "original_score"
        ]
    )

    # Không transform nào được lặp.
    applied_greedy = result[
        "applied_transforms"
    ]

    assert (
        len(applied_greedy)
        == len(
            set(applied_greedy)
        )
    )

    # Không vượt budget.
    assert (
        len(applied_greedy)
        <= 5
    )

    assert (
        result[
            "total_queries"
        ]
        >= 1
    )

    print(
        "GREEDY ATTACK TEST PASSED"
    )

    # ========================================================
    # DONE
    # ========================================================

    print(
        "\n================================"
    )

    print(
        "ALL ATTACK PIPELINE TESTS PASSED"
    )

    print(
        "================================"
    )


if __name__ == "__main__":
    main()