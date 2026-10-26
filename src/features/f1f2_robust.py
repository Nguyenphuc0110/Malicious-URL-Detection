"""Experimental robust fusion of lexical and character n-gram features."""

import re

import numpy as np
from scipy import sparse
from sklearn.preprocessing import StandardScaler

from src.features.f1_lexical import build_f1_matrix
from src.features.f2_no_www import F2VectorizerNoWWW
from src.features.url_root_normalization import ensure_root_slash


class F1F2RobustVectorizer:
    def __init__(self):
        self.f2 = F2VectorizerNoWWW()
        self.scaler = StandardScaler()

    @staticmethod
    def _prepare(urls):
        result = []

        for url in urls:
            text = str(url)

            # Remove leading www only in the experimental
            # feature representation, not in stored data.
            text = re.sub(
                r"^(https?://)www\.",
                r"\1",
                text,
                flags=re.IGNORECASE,
            )

            # Canonicalize an empty root path to "/".
            text = ensure_root_slash(text)
            result.append(text)

        return result

    @staticmethod
    def _lexical(urls):
        values = build_f1_matrix(urls).to_numpy(
            dtype=np.float32
        )
        return np.log1p(values)

    def fit(self, urls):
        prepared = self._prepare(urls)

        lexical = self._lexical(prepared)
        self.scaler.fit(lexical)

        # Fit vocabulary on TRAIN only.
        self.f2.fit(prepared)

        return self

    def transform(self, urls):
        prepared = self._prepare(urls)

        lexical = self._lexical(prepared)

        lexical = self.scaler.transform(
            lexical
        ).astype(np.float32)

        lexical_sparse = sparse.csr_matrix(lexical)

        ngrams = self.f2.transform(prepared)

        return sparse.hstack(
            [lexical_sparse, ngrams],
            format="csr",
            dtype=np.float32,
        )
