"use strict";

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const scanButton = document.getElementById("scan-button");
const buttonLabel = scanButton.querySelector("span:last-child");

const statusMessage = document.getElementById("status-message");
const resultsSection = document.getElementById("results-section");

const MODEL_CONFIG = [
    {
        name: "XGB-F1 Baseline",
        prefix: "baseline"
    },
    {
        name: "XGB-F1-D3 (Adversarial Training)",
        prefix: "defense"
    }
];

function setStatus(message, type = "") {
    statusMessage.textContent = message;
    statusMessage.className = "form-status";

    if (type) {
        statusMessage.classList.add(type);
    }
}

function validateInput(value) {
    const url = value.trim();

    if (!url) {
        throw new Error("Bạn chưa nhập URL.");
    }

    if (url.length > 2048) {
        throw new Error("URL vượt quá 2048 ký tự.");
    }

    if (/\s/.test(url)) {
        throw new Error("URL không được chứa khoảng trắng.");
    }

    if (!/^https?:\/\//i.test(url)) {
        throw new Error(
            "URL phải bắt đầu bằng http:// hoặc https://."
        );
    }

    try {
        const parsed = new URL(url);

        if (!parsed.hostname) {
            throw new Error("Missing hostname");
        }
    } catch {
        throw new Error("Định dạng URL không hợp lệ.");
    }

    return url;
}

function renderModel(result, prefix) {
    const scoreElement = document.getElementById(
        `${prefix}-score`
    );

    const thresholdElement = document.getElementById(
        `${prefix}-threshold`
    );

    const meterElement = document.getElementById(
        `${prefix}-meter`
    );

    const statusElement = document.getElementById(
        `${prefix}-status`
    );

    const score = result.score;
    const threshold = result.threshold;

    scoreElement.textContent = score.toFixed(4);
    thresholdElement.textContent = threshold.toFixed(4);

    const percentage = Math.max(
        0,
        Math.min(100, score * 100)
    );

    meterElement.style.width = `${percentage}%`;

    statusElement.className = "detection-status";

    if (result.suspicious) {
        statusElement.classList.add("danger");
        statusElement.textContent = "⚠ Nghi ngờ độc hại";
    } else {
        statusElement.classList.add("safe");
        statusElement.textContent = "✓ Chưa phát hiện độc hại";
    }
}

form.addEventListener("submit", async function (event) {
    event.preventDefault();

    resultsSection.hidden = true;
    setStatus("");

    let url;

    try {
        url = validateInput(urlInput.value);
    } catch (error) {
        setStatus(error.message, "error");
        return;
    }

    scanButton.disabled = true;
    scanButton.setAttribute("aria-busy", "true");
    buttonLabel.textContent = "Đang phân tích...";

    setStatus(
        "Đang chạy hai mô hình Machine Learning...",
        "loading"
    );

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                typeof data.detail === "string"
                    ? data.detail
                    : "Máy chủ không thể xử lý yêu cầu."
            );
        }

        if (!Array.isArray(data.results)) {
            throw new Error("Dữ liệu kết quả không hợp lệ.");
        }

        const validatedResults = MODEL_CONFIG.map(
            ({ name, prefix }) => {
                const result = data.results.find(
                    item => item.model === name
                );

                if (
                    !result ||
                    typeof result.score !== "number" ||
                    typeof result.threshold !== "number" ||
                    !Number.isFinite(result.score) ||
                    !Number.isFinite(result.threshold) ||
                    result.score < 0 ||
                    result.score > 1 ||
                    result.threshold < 0 ||
                    result.threshold > 1 ||
                    typeof result.suspicious !== "boolean"
                ) {
                    throw new Error(
                        "Kết quả mô hình không hợp lệ."
                    );
                }

                return { result, prefix };
            }
        );

        validatedResults.forEach(
            ({ result, prefix }) => {
                renderModel(result, prefix);
            }
        );

        resultsSection.hidden = false;

        setStatus("Phân tích hoàn tất.");

        resultsSection.scrollIntoView({
            behavior: window.matchMedia(
                "(prefers-reduced-motion: reduce)"
            ).matches ? "auto" : "smooth",
            block: "start"
        });

    } catch (error) {
        setStatus(
            error.message || "Không thể kết nối với máy chủ.",
            "error"
        );

    } finally {
        scanButton.disabled = false;
        scanButton.removeAttribute("aria-busy");
        buttonLabel.textContent = "Scan URL";
    }
});

/* DIGITAL FORENSIC BINARY V1 */

(function () {
    if (document.querySelector(".binary-rain")) {
        return;
    }

    function createColumn(side) {
        const element = document.createElement("div");

        element.className = "binary-rain binary-" + side;
        element.setAttribute("aria-hidden", "true");

        document.body.appendChild(element);

        return element;
    }

    const left = createColumn("left");
    const right = createColumn("right");

    function generateBinary() {
        const lines = [];

        for (let i = 0; i < 55; i++) {
            let line = "";

            for (let j = 0; j < 5; j++) {
                line += Math.random() < 0.5 ? "0  " : "1  ";
            }

            lines.push(line.trim());
        }

        return lines.join("\n");
    }

    function updateBinary() {
        left.textContent = generateBinary();
        right.textContent = generateBinary();
    }

    updateBinary();

    if (!window.matchMedia(
        "(prefers-reduced-motion: reduce)"
    ).matches) {
        setInterval(updateBinary, 6000);
    }
})();

