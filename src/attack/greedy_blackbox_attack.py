from typing import Callable, Dict, List, Set

from src.attack.transforms import (
    TRANSFORM_FUNCTIONS,
    validate_transform,
)


def greedy_blackbox_attack(
    url: str,
    max_k: int,
    predict_proba_fn: Callable[[List[str]], float],
    threshold: float,
    benign_domains_set: Set[str],
) -> Dict:
    """
    Greedy black-box attack.

    Mỗi bước:
    1. Thử tất cả transform chưa dùng.
    2. Giữ các candidate hợp lệ.
    3. Query malicious score.
    4. Chọn candidate làm score giảm nhiều nhất.
    5. Dừng khi score < threshold hoặc hết budget.

    predict_proba_fn:
        Nhận List[str]
        Trả malicious probability dạng float.
    """

    if max_k < 0:
        raise ValueError(
            "max_k must be >= 0"
        )

    # ========================================================
    # INITIAL STATE
    # ========================================================

    current_url = url

    current_score = float(
        predict_proba_fn(
            [current_url]
        )
    )

    total_queries = 1

    applied_transforms = []

    score_history = [
        current_score
    ]

    remaining_codes = list(
        TRANSFORM_FUNCTIONS.keys()
    )

    # Nếu ban đầu đã dưới threshold
    if current_score < threshold:

        return {
            "original_url": url,
            "adv_url": current_url,
            "original_score": current_score,
            "final_score": current_score,
            "is_evaded": True,
            "total_queries": total_queries,
            "applied_transforms": applied_transforms,
            "score_history": score_history,
        }

    # Không thể dùng quá số transform hiện có
    max_steps = min(
        max_k,
        len(remaining_codes),
    )

    # ========================================================
    # GREEDY LOOP
    # ========================================================

    for _ in range(max_steps):

        candidates = []

        # ----------------------------------------------------
        # GENERATE VALID CANDIDATES
        # ----------------------------------------------------

        for code in list(
            remaining_codes
        ):

            transform_fn = (
                TRANSFORM_FUNCTIONS[
                    code
                ]
            )

            candidate_url = transform_fn(
                current_url
            )

            is_valid = validate_transform(
                current_url,
                candidate_url,
                code,
                benign_domains_set,
            )

            if is_valid:

                candidates.append(
                    (
                        code,
                        candidate_url,
                    )
                )

        # Không còn candidate hợp lệ
        if not candidates:
            break

        # ----------------------------------------------------
        # QUERY ALL CANDIDATES
        # ----------------------------------------------------

        best_code = None
        best_url = None
        best_score = current_score

        for code, candidate_url in candidates:

            score = float(
                predict_proba_fn(
                    [
                        candidate_url
                    ]
                )
            )

            total_queries += 1

            # Chỉ nhận candidate nếu score giảm
            if score < best_score:

                best_score = score
                best_code = code
                best_url = candidate_url

        # Không transform nào làm giảm score
        if best_url is None:
            break

        # ----------------------------------------------------
        # ACCEPT BEST CANDIDATE
        # ----------------------------------------------------

        current_url = best_url
        current_score = best_score

        applied_transforms.append(
            best_code
        )

        score_history.append(
            current_score
        )

        # Không được dùng lại transform đã dùng
        remaining_codes.remove(
            best_code
        )

        # ----------------------------------------------------
        # SUCCESS CONDITION
        # ----------------------------------------------------

        if current_score < threshold:
            break

    # ========================================================
    # RESULT
    # ========================================================

    return {
        "original_url": url,
        "adv_url": current_url,
        "original_score": score_history[0],
        "final_score": current_score,
        "is_evaded": (
            current_score
            < threshold
        ),
        "total_queries": total_queries,
        "applied_transforms": applied_transforms,
        "score_history": score_history,
    }


# ============================================================
# DUMMY MODEL FOR SELF TEST
# ============================================================

def dummy_predict_proba(
    urls
):
    """
    Dummy model chỉ dùng để smoke test code.

    KHÔNG dùng kết quả này trong E3/report.
    """

    url = urls[0].lower()

    score = 0.95

    # HTTPS làm score giảm
    if url.startswith(
        "https://"
    ):
        score -= 0.15

    # Tracking param làm score giảm
    if "utm_" in url:
        score -= 0.15

    # Keyword trung tính sau T3
    if "member" in url:
        score -= 0.25

    if "portal" in url:
        score -= 0.15

    # Giới hạn 0.01 - 0.99
    return max(
        0.01,
        min(
            0.99,
            score,
        ),
    )


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

    test_url = (
        "http://secure-login-paypal-test.com/"
        "verify/account"
    )

    result = greedy_blackbox_attack(
        url=test_url,
        max_k=5,
        predict_proba_fn=dummy_predict_proba,
        threshold=0.5,
        benign_domains_set=benign_domains,
    )

    print(
        "=== GREEDY SELF TEST ==="
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

    # ========================================================
    # ASSERTIONS
    # ========================================================

    assert (
        result[
            "total_queries"
        ]
        >= 1
    )

    assert (
        len(
            result[
                "applied_transforms"
            ]
        )
        <= 5
    )

    assert (
        len(
            result[
                "applied_transforms"
            ]
        )
        == len(
            set(
                result[
                    "applied_transforms"
                ]
            )
        )
    )

    assert (
        result[
            "final_score"
        ]
        <= result[
            "original_score"
        ]
    )

    print(
        "\nGREEDY ATTACK SELF TEST PASSED"
    )