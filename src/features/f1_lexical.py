"""F1 — Lexical handcrafted features (Task B2, owner: Dũng).

Theo tài liệu hướng dẫn: độ dài URL/host/path, số dấu chấm, gạch, chữ số,
ký tự đặc biệt, có IP, có từ khóa đáng ngờ, entropy.

Nguyên tắc:
  * Chỉ dùng chuỗi URL (không WHOIS, không tải trang).
  * Hàm nhận URL ĐÃ chuẩn hóa (Task A4 của Phúc) nhưng vẫn chịu được URL
    thiếu scheme / có scheme.
  * Module này được Phúc (A6) và Hiếu (D2..D5) import lại -> KHÔNG viết lại ở nơi khác.

Cột 'has_https' / 'has_www' KHÔNG nằm trong F1 chuẩn (vì là đặc điểm định
dạng nguồn, dễ thành artifact). Chỉ bật khi chạy E1 để "dò" artifact:
    extract_f1(url, with_format_flags=True)
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable, List
from urllib.parse import urlsplit

import numpy as np
import pandas as pd

# Từ khóa đáng ngờ phổ biến trong phishing (danh sách này ghi vào báo cáo phần Methodology)
SUSPICIOUS_KEYWORDS = (
    "login", "signin", "sign-in", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "password", "passwd", "bank", "banking",
    "paypal", "wallet", "webscr", "support", "billing", "invoice", "suspend",
    "unlock", "authenticate", "credential", "ebay", "apple", "microsoft",
)

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IP_HEX = re.compile(r"^0x[0-9a-f]+$", re.I)
_IP_DEC = re.compile(r"^\d{8,10}$")  # dạng số thập phân của IP, vd 3232235777

F1_FEATURE_NAMES: List[str] = [
    "url_len", "host_len", "path_len", "query_len",
    "n_dots", "n_hyphens", "n_digits", "n_special",
    "n_subdomain_dots", "digit_ratio", "has_ip",
    "n_suspicious_kw", "entropy", "n_slashes", "n_params",
]
FORMAT_FLAG_NAMES: List[str] = ["has_https", "has_www"]


def _split(url: str):
    """Tách host/path/query, chịu được URL thiếu scheme."""
    u = url.strip()
    had_scheme = "://" in u
    parsed = urlsplit(u if had_scheme else "http://" + u)
    host = (parsed.hostname or "").lower()
    return had_scheme, parsed.scheme, host, parsed.path or "", parsed.query or ""


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_ip_host(host: str) -> bool:
    return bool(_IPV4.match(host) or _IP_HEX.match(host) or _IP_DEC.match(host))


def extract_f1(url: str, with_format_flags: bool = False) -> dict:
    """Trả về dict feature F1 cho 1 URL."""
    url = "" if url is None else str(url)
    had_scheme, scheme, host, path, query = _split(url)
    lower = url.lower()

    n_digits = sum(ch.isdigit() for ch in url)
    n_special = sum((not ch.isalnum()) and ch not in "./:-" for ch in url)
    host_parts = host.split(".") if host else []

    feats = {
        "url_len": len(url),
        "host_len": len(host),
        "path_len": len(path),
        "query_len": len(query),
        "n_dots": url.count("."),
        "n_hyphens": url.count("-"),
        "n_digits": n_digits,
        "n_special": n_special,
        # số dấu chấm trong host - 1 (~ số subdomain, xấp xỉ, chưa xử lý suffix kép)
        "n_subdomain_dots": max(len(host_parts) - 2, 0),
        "digit_ratio": (n_digits / len(url)) if url else 0.0,
        "has_ip": int(is_ip_host(host)),
        "n_suspicious_kw": sum(kw in lower for kw in SUSPICIOUS_KEYWORDS),
        "entropy": shannon_entropy(url),
        "n_slashes": path.count("/"),
        "n_params": (query.count("&") + 1) if query else 0,
    }
    if with_format_flags:
        feats["has_https"] = int(scheme == "https")
        feats["has_www"] = int(host.startswith("www."))
    return feats


def build_f1_matrix(urls: Iterable[str], with_format_flags: bool = False) -> pd.DataFrame:
    """Ma trận F1 (mỗi dòng 1 URL). Cột theo thứ tự cố định để train/test khớp nhau."""
    rows = [extract_f1(u, with_format_flags) for u in urls]
    cols = F1_FEATURE_NAMES + (FORMAT_FLAG_NAMES if with_format_flags else [])
    df = pd.DataFrame(rows, columns=cols)
    if df.isna().any().any():
        raise ValueError("F1 có NaN — kiểm tra lại URL đầu vào")
    return df.astype(np.float32)
