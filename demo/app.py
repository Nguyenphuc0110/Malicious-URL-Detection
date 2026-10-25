"""AIC211 Malicious URL Detection - Streamlit demo."""

import math
import sys
from pathlib import Path
from urllib.parse import urlsplit

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.models.detector import URLDetector


st.set_page_config(
    page_title="Malicious URL Detector | AIC211",
    page_icon="🛡️",
    layout="centered",
)

MODEL_FILES = {
    "XGB-F1 Baseline": ROOT / "models" / "xgb_f1.joblib",
    "XGB-F1-D3 (Adversarial Training)": (
        ROOT / "models" / "xgb_f1_d3.joblib"
    ),
}


@st.cache_resource(show_spinner="Đang tải các mô hình AI...")
def load_models():
    return {
        name: URLDetector.load(str(path))
        for name, path in MODEL_FILES.items()
    }


def validate_url(value):
    url = value.strip()

    if not url:
        return None, "Bạn chưa nhập URL."

    if len(url) > 2048:
        return None, "URL vượt quá giới hạn 2048 ký tự."

    if any(char.isspace() for char in url):
        return None, "URL không được chứa khoảng trắng."

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return None, "URL phải bắt đầu bằng http:// hoặc https://."

        if not parsed.hostname:
            return None, "URL phải có tên miền hoặc địa chỉ IP."

        _ = parsed.port

    except ValueError:
        return None, "URL không hợp lệ."

    return url, None


st.title("🛡️ Malicious URL Detector")
st.write(
    "Hệ thống phát hiện URL đáng ngờ bằng Machine Learning."
)
st.caption(
    "Đồ án AIC211 — Malicious URL Detection & Robustness Research"
)

st.divider()

with st.form("url_form"):
    entered_url = st.text_input(
        "Nhập địa chỉ URL cần kiểm tra",
        placeholder="https://example.com/login",
    )

    submitted = st.form_submit_button(
        "🔍 Phân tích URL",
        type="primary",
        use_container_width=True,
    )

if submitted:
    url, error = validate_url(entered_url)

    if error:
        st.warning(error)

    else:
        try:
            models = load_models()

            st.subheader("Kết quả phân tích")

            columns = st.columns(2)

            for column, (name, detector) in zip(
                columns, models.items()
            ):
                with column:
                    score = float(detector.score([url])[0])
                    threshold = float(detector.threshold)

                    if not math.isfinite(score):
                        raise ValueError("Invalid model score")

                    st.markdown(f"**{name}**")

                    if score >= threshold:
                        st.error("⚠️ Nghi ngờ độc hại")
                    else:
                        st.info("ℹ️ Chưa phát hiện độc hại")

                    st.metric(
                        "Điểm mô hình",
                        f"{score:.4f}",
                    )

                    st.caption(
                        f"Ngưỡng phát hiện: {threshold:.4f}"
                    )

            st.divider()

            st.write(
                "**Lưu ý:** Điểm mô hình không phải "
                "xác suất URL an toàn. Kết quả âm tính "
                "không đảm bảo URL không nguy hiểm."
            )

        except Exception:
            st.error(
                "Không thể phân tích URL. "
                "Hãy kiểm tra các file model và thử lại."
            )

st.divider()

st.caption(
    "Hệ thống chỉ phân tích đặc trưng chuỗi URL. "
    "Không mở URL, không tải nội dung trang web "
    "và không kiểm tra trạng thái website."
)
