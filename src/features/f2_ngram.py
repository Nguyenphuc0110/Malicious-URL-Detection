"""F2 — Char n-gram TF-IDF (Task B3, owner: Dũng).

  * TF-IDF ký tự 3–5 gram, TÁCH RIÊNG cho host và cho path(+query).
  * fit CHỈ trên tập train. Val/test/nguồn B/C chỉ transform (KHÔNG fit lại) —
    fit lại trên tập khác là rò rỉ dữ liệu và làm sai E2.
  * Vectorizer đã fit được lưu bằng joblib để Phúc (A6) và Hiếu (D2) dùng lại đúng
    vocabulary.

Cách dùng:
    vec = F2Vectorizer().fit(train_urls)
    X_train = vec.transform(train_urls)
    vec.save("models/f2_vectorizer.joblib")
    vec = F2Vectorizer.load("models/f2_vectorizer.joblib")
"""
from __future__ import annotations

from typing import Iterable, List, Tuple
from urllib.parse import urlsplit

import joblib
import numpy as np
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer


def split_host_path(url: str) -> Tuple[str, str]:
    """Trả (host, path+query). Chịu được URL thiếu scheme."""
    u = "" if url is None else str(url).strip()
    parsed = urlsplit(u if "://" in u else "http://" + u)
    host = (parsed.hostname or "").lower()
    rest = (parsed.path or "") + (("?" + parsed.query) if parsed.query else "")
    return host, rest.lower()


class F2Vectorizer:
    def __init__(self, ngram_range=(3, 5), max_features_host=100_000,
                 max_features_path=200_000, min_df=2):
        self.ngram_range = ngram_range
        self.host_vec = TfidfVectorizer(
            analyzer="char", ngram_range=ngram_range, lowercase=True,
            sublinear_tf=True, min_df=min_df, max_features=max_features_host,
            dtype=np.float32,
        )
        self.path_vec = TfidfVectorizer(
            analyzer="char", ngram_range=ngram_range, lowercase=True,
            sublinear_tf=True, min_df=min_df, max_features=max_features_path,
            dtype=np.float32,
        )
        self._fitted = False

    def _parts(self, urls: Iterable[str]) -> Tuple[List[str], List[str]]:
        hosts, paths = [], []
        for u in urls:
            h, p = split_host_path(u)
            hosts.append(h)
            paths.append(p)
        return hosts, paths

    def fit(self, train_urls: Iterable[str]) -> "F2Vectorizer":
        hosts, paths = self._parts(train_urls)
        self.host_vec.fit(hosts)
        self.path_vec.fit(paths)
        self._fitted = True
        return self

    def transform(self, urls: Iterable[str]) -> sp.csr_matrix:
        if not self._fitted:
            raise RuntimeError("F2Vectorizer chưa fit — chỉ fit trên TRAIN rồi mới transform")
        hosts, paths = self._parts(urls)
        return sp.hstack(
            [self.host_vec.transform(hosts), self.path_vec.transform(paths)],
            format="csr",
        )

    @property
    def n_features(self) -> Tuple[int, int]:
        return len(self.host_vec.vocabulary_), len(self.path_vec.vocabulary_)

    def save(self, path: str) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str) -> "F2Vectorizer":
        return joblib.load(path)
