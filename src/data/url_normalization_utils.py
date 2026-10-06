import pandas as pd

from urllib.parse import (
    urlsplit,
    urlunsplit,
)


def normalize_url(url):
    """
    Normalize URL while keeping information useful for ML.

    Rules:
    - Remove leading/trailing whitespace
    - Add http:// if scheme is missing
    - Lowercase scheme
    - Lowercase hostname
    - Preserve path
    - Preserve query string
    - Preserve non-default port
    - Remove fragment (#...)
    """

    if pd.isna(url):
        return None

    url = str(url).strip()

    if not url:
        return None

    # Add scheme if missing
    if "://" not in url:
        url = "http://" + url

    try:
        parts = urlsplit(url)

        scheme = parts.scheme.lower()

        hostname = parts.hostname

        if not hostname:
            return None

        hostname = hostname.lower()

        # Check port
        try:
            port = parts.port
        except ValueError:
            return None

        # Remove default ports
        if (
            (scheme == "http" and port == 80)
            or
            (scheme == "https" and port == 443)
        ):
            port = None

        if port:
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        path = parts.path
        query = parts.query

        # Fragment intentionally removed
        fragment = ""

        normalized = urlunsplit(
            (
                scheme,
                netloc,
                path,
                query,
                fragment,
            )
        )

        return normalized

    except Exception:
        return None