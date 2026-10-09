import random
from typing import List, Set, Tuple

from src.attack.transforms import (
    TRANSFORM_FUNCTIONS,
    validate_transform,
)


def random_attack(
    url: str,
    k: int,
    benign_domains_set: Set[str],
) -> Tuple[str, List[str]]:
    """
    Random attack.

    k:
        số transform tối đa.

    Mỗi loại T1-T7 chỉ được dùng tối đa 1 lần.
    """

    if k < 0:
        raise ValueError(
            "k must be >= 0"
        )

    if k == 0:
        return url, []

    current_url = url

    applied = []

    available_codes = list(
        TRANSFORM_FUNCTIONS.keys()
    )

    max_steps = min(
        k,
        len(available_codes),
    )

    for _ in range(
        max_steps
    ):

        random.shuffle(
            available_codes
        )

        success = False

        # list(...) để có thể remove an toàn.
        for code in list(
            available_codes
        ):

            transform_fn = (
                TRANSFORM_FUNCTIONS[
                    code
                ]
            )

            candidate = transform_fn(
                current_url
            )

            if validate_transform(
                current_url,
                candidate,
                code,
                benign_domains_set,
            ):
                current_url = candidate

                applied.append(
                    code
                )

                # Không cho dùng lại transform này.
                available_codes.remove(
                    code
                )

                success = True

                break

        if not success:
            break

        if not available_codes:
            break

    return (
        current_url,
        applied,
    )


if __name__ == "__main__":

    random.seed(
        42
    )

    benign_domains = {
        "google.com",
        "facebook.com",
        "paypal.com",
    }

    url = (
        "http://secure-login-paypal-test.com/"
        "verify/account"
    )

    for k in [
        0,
        1,
        2,
        3,
        5,
    ]:

        adv_url, applied = random_attack(
            url=url,
            k=k,
            benign_domains_set=benign_domains,
        )

        print(
            "\nk =",
            k
        )

        print(
            "original:",
            url
        )

        print(
            "adv     :",
            adv_url
        )

        print(
            "applied :",
            applied
        )

        assert (
            len(applied)
            == len(set(applied))
        )

        assert (
            len(applied)
            <= k
        )

    print(
        "\nRANDOM ATTACK SELF TEST PASSED"
    )
    