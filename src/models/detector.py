"""URLDetector — giao diện thống nhất cho MỌI model (Task B4, owner: Dũng).

Vì sao cần lớp này:
  * Nam (C2/C3/C4) tấn công HỘP ĐEN: chỉ được gọi  detector.score(urls)  và nhận
    điểm độc hại — không được đọc feature/trọng số. Lớp này ép đúng ràng buộc đó.
  * Hiếu (D3) cắm D1 (chuẩn hóa punycode/homoglyph/tracking-param) qua tham số
    `preprocess` — không phải sửa code của Dũng.
  * Hiếu (D4) cắm feature D2 bằng cách tạo detector mới với `feature_kind` khác.

    det = URLDetector.load("models/rf_f1.joblib")
    scores = det.score(["http://a.com/x", "..."])      # np.ndarray, [0,1], 1 = độc hại
    labels = det.predict(urls)                          # dùng det.threshold
"""
from __future__ import annotations

from typing import Callable, Iterable, Optional, Sequence

import joblib
import numpy as np

from src.features.f1_lexical import build_f1_matrix
from src.features.f2_ngram import F2Vectorizer


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -50, 50)))


class URLDetector:
    def __init__(self, name: str, feature_kind: str, model,
                 f2_vectorizer: Optional[F2Vectorizer] = None,
                 preprocess: Optional[Callable[[str], str]] = None,
                 threshold: Optional[float] = None):
        if feature_kind not in ("f1", "f2", "f1d2"):
            raise ValueError("feature_kind must be f1, f2 or f1d2")
        if feature_kind == "f2" and f2_vectorizer is None:
            raise ValueError("feature_kind must be f1, f2 or f1d2")
        self.name = name
        self.feature_kind = feature_kind
        self.model = model
        self.f2_vectorizer = f2_vectorizer
        self.preprocess = preprocess      # hook cho D1 của Hiếu
        self.threshold = threshold        # chọn trên validation A (FPR≈1%), rồi GIỮ NGUYÊN

    # ---- features -------------------------------------------------------
    def _prep(self, urls: Iterable[str]) -> list:
        urls = [("" if u is None else str(u)) for u in urls]
        if self.preprocess is not None:
            urls = [self.preprocess(u) for u in urls]
        return urls

    def featurize(self, urls: Sequence[str]):
        """Dành cho phân tích nội bộ (SHAP...). Tấn công hộp đen KHÔNG được gọi hàm này."""
        urls = self._prep(urls)
        if self.feature_kind == "f1":
            return build_f1_matrix(urls)
        if self.feature_kind == "f1d2":
            from src.features.f1_d2 import build_f1_d2_matrix
            return build_f1_d2_matrix(urls)
        return self.f2_vectorizer.transform(urls)

    # ---- scoring --------------------------------------------------------
    def score(self, urls: Sequence[str]) -> np.ndarray:
        """Điểm độc hại trong [0,1]; lớn hơn = đáng ngờ hơn."""
        X = self.featurize(urls)
        if hasattr(self.model, "predict_proba"):
            return np.asarray(self.model.predict_proba(X)[:, 1], dtype=np.float64)
        if hasattr(self.model, "decision_function"):     # LinearSVC
            return _sigmoid(np.asarray(self.model.decision_function(X), dtype=np.float64))
        raise TypeError("Model không có predict_proba/decision_function")

    def predict(self, urls: Sequence[str]) -> np.ndarray:
        if self.threshold is None:
            raise RuntimeError("Chưa đặt threshold (chọn trên validation A để FPR≈1%)")
        return (self.score(urls) >= self.threshold).astype(int)

    # ---- io -------------------------------------------------------------
    def save(self, path: str) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str) -> "URLDetector":
        return joblib.load(path)

    def __repr__(self) -> str:
        return f"URLDetector(name={self.name!r}, feature={self.feature_kind}, thr={self.threshold})"
