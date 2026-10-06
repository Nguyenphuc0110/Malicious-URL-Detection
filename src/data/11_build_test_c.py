from pathlib import Path

from urllib.parse import urlsplit

import ipaddress



import pandas as pd

import tldextract

from url_normalization_utils import normalize_url





# ============================================================

# CONFIG

# ============================================================



RANDOM_SEED = 42



TARGET_PER_CLASS = 18_000



ROOT = Path(".")



# Source A

SOURCE_A_DEDUP = Path(

    "data/processed/source_a_dedup.csv"

)



TRAIN_A = Path(

    "data/processed/handoff/train.csv"

)



# Source C benign real-path collected from Common Crawl

COMMONCRAWL_BENIGN = Path(

    "data/raw/source_c_commoncrawl_benign.csv"

)



# Tranco

TRANCO_RAW = Path(

    "data/raw/source_c/tranco/top-1m.csv"

)



# Final output

OUTPUT_FILE = Path(

    "data/processed/handoff/test_C.csv"

)



# Logs

LOG_DIR = Path(

    "outputs/logs"

)





# ============================================================

# TLD EXTRACT

# ============================================================



# Offline mode.

# Không tải Public Suffix List từ Internet.

TLD_EXTRACT = tldextract.TLDExtract(

    suffix_list_urls=None

)





# ============================================================

# HELPERS

# ============================================================



def find_url_column(df):

    """

    Tìm cột URL trong DataFrame.

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





def registered_domain_from_url(url):

    """

    Extract registered domain.



    Với IP:

        trả chính IP.



    Với domain:

        sử dụng top_domain_under_public_suffix.

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



    host = host.lower().strip(".")



    # --------------------------------------------------------

    # IP address

    # --------------------------------------------------------



    try:



        ipaddress.ip_address(

            host

        )



        return host



    except ValueError:



        pass





    # --------------------------------------------------------

    # Normal domain

    # --------------------------------------------------------



    ext = TLD_EXTRACT(

        host

    )



    registered = (

        ext.top_domain_under_public_suffix

    )



    if registered:

        return registered.lower()



    # Fallback cho unusual hostname

    return host





def has_real_path(url):

    """

    Real path:

        path khác "" và "/".

    """



    try:



        path = urlsplit(

            str(url)

        ).path



    except Exception:



        return False



    return (

        path not in (

            "",

            "/",

        )

    )





def normalize_series(series):

    """

    Apply cùng normalize_url() của pipeline A/B.

    """



    return series.apply(

        normalize_url

    )





# ============================================================

# LOAD SOURCE A REFERENCE

# ============================================================



def load_source_a_reference():

    """

    Load:

        - toàn bộ normalized URL Source A

        - registered domains của train A

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

    # Source A URLs

    # --------------------------------------------------------



    a = pd.read_csv(

        SOURCE_A_DEDUP,

        low_memory=False

    )



    a_url_col = find_url_column(

        a

    )



    source_a_urls = set(

        a[a_url_col]

        .dropna()

        .astype(str)

        .str.strip()

    )





    # --------------------------------------------------------

    # Train A registered domains

    # --------------------------------------------------------



    train = pd.read_csv(

        TRAIN_A,

        usecols=[

            "registered_domain"

        ]

    )



    train_domains = set(

        train["registered_domain"]

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

        train_domains

    )





# ============================================================

# LOAD MALICIOUS SOURCE C

# ============================================================



def load_source_c_malicious():

    """

    Load phishing Source C.



    Ưu tiên file malicious đã prepare.



    Nếu không có, fallback sang

    source_c_normalized.csv và filter malicious.

    """



    print(

        "\n=== LOAD SOURCE C MALICIOUS ==="

    )





    candidates = [



        Path(

            "data/processed/source_c_malicious.csv"

        ),



        Path(

            "data/raw/source_c_malicious.csv"

        ),

    ]





    for path in candidates:



        if path.exists():



            print(

                "Using:",

                path

            )



            df = pd.read_csv(

                path,

                low_memory=False

            )



            url_col = find_url_column(

                df

            )



            result = pd.DataFrame(

                {

                    "url":

                        df[url_col]

                }

            )



            return result





    # ========================================================

    # FALLBACK: SOURCE C NORMALIZED

    # ========================================================



    fallback = Path(

        "data/processed/source_c_normalized.csv"

    )



    if not fallback.exists():



        raise FileNotFoundError(

            "Cannot find Source C malicious data."

        )





    print(

        "Using fallback:",

        fallback

    )





    df = pd.read_csv(

        fallback,

        low_memory=False

    )



    url_col = find_url_column(

        df

    )





    # --------------------------------------------------------

    # Find class column

    # --------------------------------------------------------



    class_candidates = [

        "orig_class",

        "type",

        "class",

        "label",

    ]



    class_col = None



    for col in class_candidates:



        if col in df.columns:



            class_col = col

            break





    if class_col is None:



        raise ValueError(

            "Cannot identify malicious rows in "

            "source_c_normalized.csv"

        )





    values = (

        df[class_col]

        .astype(str)

        .str.lower()

        .str.strip()

    )





    malicious_values = {

        "1",

        "malicious",

        "phishing",

        "phish",

        "malware",

    }





    mask = values.isin(

        malicious_values

    )





    result = pd.DataFrame(

        {

            "url":

                df.loc[

                    mask,

                    url_col

                ]

        }

    )





    return result





# ============================================================

# CLEAN MALICIOUS

# ============================================================



def clean_malicious(

    malicious,

    source_a_urls,

    train_domains

):

    """

    Normalize + dedup + overlap filtering.

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

    # Drop missing

    # --------------------------------------------------------



    malicious = malicious[

        malicious["url"].notna()

    ].copy()





    malicious["url"] = (

        malicious["url"]

        .astype(str)

        .str.strip()

    )





    malicious = malicious[

        malicious["url"] != ""

    ].copy()





    # --------------------------------------------------------

    # Normalize

    # --------------------------------------------------------



    malicious["url"] = normalize_series(

        malicious["url"]

    )





    normalization_failed = int(

        malicious["url"]

        .isna()

        .sum()

    )





    malicious = malicious[

        malicious["url"].notna()

    ].copy()





    print(

        "Normalization failed:",

        normalization_failed

    )





    # --------------------------------------------------------

    # Internal dedup

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

    # Registered domain

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





    malicious = malicious[

        malicious[

            "registered_domain"

        ].notna()

    ].copy()





    print(

        "Missing registered_domain:",

        missing_domain

    )





    # --------------------------------------------------------

    # Exact URL overlap Source A

    # --------------------------------------------------------



    exact_mask = malicious[

        "url"

    ].isin(

        source_a_urls

    )





    exact_removed = int(

        exact_mask.sum()

    )





    malicious = malicious[

        ~exact_mask

    ].copy()





    print(

        "Exact URL overlap A removed:",

        exact_removed

    )





    # --------------------------------------------------------

    # Domain overlap TRAIN A

    # --------------------------------------------------------



    domain_mask = malicious[

        "registered_domain"

    ].str.lower().isin(

        train_domains

    )





    domain_removed = int(

        domain_mask.sum()

    )





    malicious = malicious[

        ~domain_mask

    ].copy()





    print(

        "Train-domain overlap removed:",

        domain_removed

    )





    # --------------------------------------------------------

    # Path info

    # --------------------------------------------------------



    malicious[

        "has_path"

    ] = malicious[

        "url"

    ].apply(

        has_real_path

    )





    print(

        "Clean malicious:",

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

# LOAD COMMON CRAWL BENIGN PATH URLS

# ============================================================



def load_commoncrawl_benign(

    source_a_urls,

    train_domains

):

    """

    Load real-path benign URL strings collected

    from Common Crawl.

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

        low_memory=False

    )





    url_col = find_url_column(

        df

    )





    benign = pd.DataFrame(

        {

            "url":

                df[url_col]

        }

    )





    benign = benign[

        benign["url"].notna()

    ].copy()





    benign["url"] = (

        benign["url"]

        .astype(str)

        .str.strip()

    )





    # --------------------------------------------------------

    # Normalize

    # --------------------------------------------------------



    benign["url"] = normalize_series(

        benign["url"]

    )





    benign = benign[

        benign["url"].notna()

    ].copy()





    # --------------------------------------------------------

    # Dedup

    # --------------------------------------------------------



    benign = (

        benign

        .drop_duplicates(

            subset=[

                "url"

            ]

        )

        .copy()

    )





    # --------------------------------------------------------

    # Only real paths

    # --------------------------------------------------------



    benign[

        "has_path"

    ] = benign[

        "url"

    ].apply(

        has_real_path

    )





    benign = benign[

        benign[

            "has_path"

        ]

    ].copy()





    # --------------------------------------------------------

    # Registered domain

    # --------------------------------------------------------



    benign[

        "registered_domain"

    ] = benign[

        "url"

    ].apply(

        registered_domain_from_url

    )





    benign = benign[

        benign[

            "registered_domain"

        ].notna()

    ].copy()





    # --------------------------------------------------------

    # Remove exact A overlap

    # --------------------------------------------------------



    benign = benign[

        ~benign[

            "url"

        ].isin(

            source_a_urls

        )

    ].copy()





    # --------------------------------------------------------

    # Remove train domain overlap

    # --------------------------------------------------------



    benign = benign[

        ~benign[

            "registered_domain"

        ].str.lower().isin(

            train_domains

        )

    ].copy()





    print(

        "Available path benign:",

        len(benign)

    )





    print(

        "Unique domains:",

        benign[

            "registered_domain"

        ].nunique()

    )





    print(

        "Path ratio:",

        f"{benign['has_path'].mean() * 100:.2f}%"

    )





    return benign





# ============================================================

# LOAD TRANCO HOMEPAGES

# ============================================================



def load_tranco_homepages(

    source_a_urls,

    train_domains

):

    """

    Load benign homepage URLs from Tranco.



    Dùng để phối hợp với Common Crawl nhằm làm

    path ratio benign gần bằng malicious.

    """



    print(

        "\n=== LOAD TRANCO HOMEPAGES ==="

    )





    if not TRANCO_RAW.exists():



        raise FileNotFoundError(

            TRANCO_RAW

        )





    # Tranco thường không có header:

    #

    # rank,domain

    #

    tranco = pd.read_csv(

        TRANCO_RAW,

        header=None,

        names=[

            "rank",

            "domain",

        ],

        usecols=[

            0,

            1,

        ],

        low_memory=False

    )





    tranco = tranco[

        tranco[

            "domain"

        ].notna()

    ].copy()





    tranco[

        "domain"

    ] = (

        tranco[

            "domain"

        ]

        .astype(str)

        .str.strip()

        .str.lower()

    )





    tranco = tranco[

        tranco[

            "domain"

        ] != ""

    ].copy()





    # --------------------------------------------------------

    # Build homepage URL

    # --------------------------------------------------------



    # HTTPS được dùng như canonical homepage representation.

    tranco[

        "url"

    ] = (

        "https://"

        + tranco[

            "domain"

        ]

    )





    # Same normalization pipeline

    tranco[

        "url"

    ] = normalize_series(

        tranco[

            "url"

        ]

    )





    tranco = tranco[

        tranco[

            "url"

        ].notna()

    ].copy()





    # --------------------------------------------------------

    # Registered domain

    # --------------------------------------------------------



    tranco[

        "registered_domain"

    ] = tranco[

        "url"

    ].apply(

        registered_domain_from_url

    )





    tranco = tranco[

        tranco[

            "registered_domain"

        ].notna()

    ].copy()





    # --------------------------------------------------------

    # Remove Train A domains

    # --------------------------------------------------------



    tranco = tranco[

        ~tranco[

            "registered_domain"

        ].str.lower().isin(

            train_domains

        )

    ].copy()





    # --------------------------------------------------------

    # Remove exact Source A URLs

    # --------------------------------------------------------



    tranco = tranco[

        ~tranco[

            "url"

        ].isin(

            source_a_urls

        )

    ].copy()





    # --------------------------------------------------------

    # Ensure homepage

    # --------------------------------------------------------



    tranco[

        "has_path"

    ] = tranco[

        "url"

    ].apply(

        has_real_path

    )





    tranco = tranco[

        ~tranco[

            "has_path"

        ]

    ].copy()





    # --------------------------------------------------------

    # Dedup

    # --------------------------------------------------------



    tranco = (

        tranco

        .drop_duplicates(

            subset=[

                "url"

            ]

        )

        .copy()

    )





    print(

        "Available Tranco homepages:",

        len(tranco)

    )





    print(

        "Unique domains:",

        tranco[

            "registered_domain"

        ].nunique()

    )





    return tranco[

        [

            "url",

            "registered_domain",

            "has_path",

        ]

    ].copy()





# ============================================================

# SAMPLE MALICIOUS

# ============================================================



def sample_malicious(

    malicious

):

    """

    Random sample TARGET_PER_CLASS malicious URLs.

    """



    if len(

        malicious

    ) < TARGET_PER_CLASS:



        raise RuntimeError(

            "Not enough malicious URLs. "

            f"Need {TARGET_PER_CLASS}, "

            f"have {len(malicious)}."

        )





    sampled = malicious.sample(

        n=TARGET_PER_CLASS,

        random_state=RANDOM_SEED

    ).copy()





    sampled[

        "label"

    ] = 1



    sampled[

        "orig_class"

    ] = "phishing"





    return sampled





# ============================================================

# BUILD MATCHED BENIGN

# ============================================================



def build_matched_benign(

    malicious_sample,

    path_benign,

    homepage_benign

):

    """

    Match benign path ratio exactly to selected malicious sample.



    Example:



        malicious:

            63% with path



        benign:

            63% Common Crawl real-path

            37% Tranco homepage

    """



    print(

        "\n=== BUILD MATCHED BENIGN ==="

    )





    malicious_path_count = int(

        malicious_sample[

            "has_path"

        ].sum()

    )





    malicious_home_count = (

        TARGET_PER_CLASS

        - malicious_path_count

    )





    print(

        "Target total benign:",

        TARGET_PER_CLASS

    )



    print(

        "Need path benign:",

        malicious_path_count

    )



    print(

        "Need homepage benign:",

        malicious_home_count

    )





    if (

        len(path_benign)

        < malicious_path_count

    ):



        raise RuntimeError(

            "Not enough Common Crawl path benign URLs. "

            f"Need {malicious_path_count}, "

            f"have {len(path_benign)}."

        )





    if (

        len(homepage_benign)

        < malicious_home_count

    ):



        raise RuntimeError(

            "Not enough Tranco homepage benign URLs. "

            f"Need {malicious_home_count}, "

            f"have {len(homepage_benign)}."

        )





    # --------------------------------------------------------

    # Sample path URLs

    # --------------------------------------------------------



    path_sample = path_benign.sample(

        n=malicious_path_count,

        random_state=RANDOM_SEED

    ).copy()





    # --------------------------------------------------------

    # Avoid domain overlap between selected path benign

    # and homepage benign where possible

    # --------------------------------------------------------



    path_domains = set(

        path_sample[

            "registered_domain"

        ]

        .astype(str)

        .str.lower()

    )





    homepage_pool = homepage_benign[

        ~homepage_benign[

            "registered_domain"

        ]

        .astype(str)

        .str.lower()

        .isin(

            path_domains

        )

    ].copy()





    # If still enough, use domain-disjoint homepage pool.

    if (

        len(homepage_pool)

        >= malicious_home_count

    ):



        homepage_source = homepage_pool



    else:



        homepage_source = homepage_benign





    homepage_sample = homepage_source.sample(

        n=malicious_home_count,

        random_state=RANDOM_SEED + 1

    ).copy()





    # --------------------------------------------------------

    # Combine

    # --------------------------------------------------------



    benign = pd.concat(

        [

            path_sample,

            homepage_sample,

        ],

        ignore_index=True

    )





    benign = benign.sample(

        frac=1,

        random_state=RANDOM_SEED

    ).reset_index(

        drop=True

    )





    benign[

        "label"

    ] = 0



    benign[

        "orig_class"

    ] = "benign"





    print(

        "Final benign:",

        len(benign)

    )





    print(

        "Benign path ratio:",

        f"{benign['has_path'].mean() * 100:.2f}%"

    )





    return benign





# ============================================================

# FINAL VALIDATION

# ============================================================



def validate_final(

    final_df,

    source_a_urls,

    train_domains

):

    """

    Hard checks before exporting test_C.csv.

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

    # Counts

    # --------------------------------------------------------



    print(

        "Rows:",

        len(final_df)

    )





    print(

        "\nLabel counts:"

    )



    print(

        final_df[

            "label"

        ].value_counts().sort_index()

    )





    print(

        "\nOrig class counts:"

    )



    print(

        final_df[

            "orig_class"

        ].value_counts()

    )





    # --------------------------------------------------------

    # Missing

    # --------------------------------------------------------



    missing_url = int(

        final_df[

            "url"

        ].isna().sum()

    )



    missing_domain = int(

        final_df[

            "registered_domain"

        ].isna().sum()

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

    # Duplicate

    # --------------------------------------------------------



    duplicate_urls = int(

        final_df[

            "url"

        ].duplicated().sum()

    )





    print(

        "Duplicate URLs:",

        duplicate_urls

    )





    # --------------------------------------------------------

    # Exact overlap Source A

    # --------------------------------------------------------



    exact_overlap = int(

        final_df[

            "url"

        ].isin(

            source_a_urls

        ).sum()

    )





    print(

        "URL overlap with Source A:",

        exact_overlap

    )





    # --------------------------------------------------------

    # Train domain overlap

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

    # Path ratio

    # --------------------------------------------------------



    final_df = final_df.copy()



    final_df[

        "has_path_check"

    ] = final_df[

        "url"

    ].apply(

        has_real_path

    )





    print(

        "\nPath ratio by label:"

    )





    for label in [

        0,

        1,

    ]:



        subset = final_df[

            final_df[

                "label"

            ] == label

        ]



        ratio = (

            subset[

                "has_path_check"

            ].mean()

            * 100

        )



        print(

            f"label {label}: "

            f"{ratio:.2f}%"

        )





    # --------------------------------------------------------

    # Hard assertions

    # --------------------------------------------------------



    assert (

        len(final_df)

        == TARGET_PER_CLASS * 2

    )





    assert (

        final_df[

            "label"

        ].value_counts().get(

            0,

            0

        )

        == TARGET_PER_CLASS

    )





    assert (

        final_df[

            "label"

        ].value_counts().get(

            1,

            0

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

        exact_overlap

        == 0

    )





    assert (

        domain_overlap

        == 0

    )





    benign_ratio = final_df.loc[

        final_df[

            "label"

        ] == 0,

        "has_path_check"

    ].mean()





    malicious_ratio = final_df.loc[

        final_df[

            "label"

        ] == 1,

        "has_path_check"

    ].mean()





    # Benign path count was constructed from malicious count,

    # so these should be identical.

    assert (

        abs(

            benign_ratio

            - malicious_ratio

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

        "BUILD FINAL TEST C"

    )



    print(

        "===================================="

    )





    OUTPUT_FILE.parent.mkdir(

        parents=True,

        exist_ok=True

    )



    LOG_DIR.mkdir(

        parents=True,

        exist_ok=True

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

        train_domains

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

        "Path rows:",

        int(

            malicious_sample[

                "has_path"

            ].sum()

        )

    )





    print(

        "Homepage rows:",

        int(

            (

                ~malicious_sample[

                    "has_path"

                ]

            ).sum()

        )

    )





    print(

        "Path ratio:",

        f"{malicious_sample['has_path'].mean() * 100:.2f}%"

    )





    # ========================================================

    # BENIGN PATHS

    # ========================================================



    path_benign = load_commoncrawl_benign(

        source_a_urls,

        train_domains

    )





    # ========================================================

    # BENIGN HOMEPAGES

    # ========================================================



    homepage_benign = load_tranco_homepages(

        source_a_urls,

        train_domains

    )





    # ========================================================

    # MATCH BENIGN SHAPE

    # ========================================================



    benign_sample = build_matched_benign(

        malicious_sample,

        path_benign,

        homepage_benign

    )





    # ========================================================

    # FORMAT

    # ========================================================



    columns = [

        "url",

        "label",

        "orig_class",

        "registered_domain",

    ]





    malicious_final = malicious_sample[

        columns

    ].copy()





    benign_final = benign_sample[

        columns

    ].copy()





    # ========================================================

    # REMOVE CROSS-CLASS COLLISION

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





    if collisions > 0:



        raise RuntimeError(

            "Benign/malicious URL collision detected: "

            f"{collisions}"

        )





    # ========================================================

    # FINAL COMBINE

    # ========================================================



    final_df = pd.concat(

        [

            benign_final,

            malicious_final,

        ],

        ignore_index=True

    )





    final_df = final_df.sample(

        frac=1,

        random_state=RANDOM_SEED

    ).reset_index(

        drop=True

    )





    # ========================================================

    # VALIDATE

    # ========================================================



    validate_final(

        final_df,

        source_a_urls,

        train_domains

    )





    # ========================================================

    # SAVE

    # ========================================================



    final_df.to_csv(

        OUTPUT_FILE,

        index=False

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

        "\nHeader:"

    )



    print(

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