"""Root URL canonicalization for experimental XGB-F1-V2."""

from urllib.parse import urlsplit, urlunsplit


def ensure_root_slash(url: str) -> str:
    """
    Normalize only an empty root path.

    https://example.com  -> https://example.com/
    https://example.com/ -> https://example.com/

    Other paths, queries and fragments are preserved.
    """
    text = str(url)

    try:
        parts = urlsplit(text)

        if (
            parts.scheme.lower() in ("http", "https")
            and parts.netloc
            and parts.path == ""
        ):
            return urlunsplit(parts._replace(path="/"))

    except ValueError:
        pass

    return text
