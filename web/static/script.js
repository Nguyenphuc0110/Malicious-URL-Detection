"use strict";

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const scanButton = document.getElementById("scan-button");
const buttonLabel = scanButton.querySelector("span:last-child");

const statusMessage = document.getElementById("status-message");
const resultsSection = document.getElementById("results-section");

const MODEL_CONFIG = [
    {
        name: "LR-F1",
        prefix: "baseline"
    },
    {
        name: "RF-F1",
        prefix: "defense"
    },
    {
        name: "XGB-F1",
        prefix: "xgb"
    },
    {
        name: "LR-F2",
        prefix: "multisource"
    },
    {
        name: "SVM-F2",
        prefix: "fusion"
    }
];


/* FIVE MODEL UI V1 */

function installExtraModelCards() {
    const grid = document.querySelector(
        "#results-section .result-grid"
    );

    const template = grid?.querySelector(".result-card");

    if (!grid || !template) {
        throw new Error("Cannot locate existing model card.");
    }

    const extraModels = [
        {
            name: "XGB-F1",
            prefix: "xgb",
            description: "XGBoost sử dụng đặc trưng từ chuỗi URL."
        },
        {
            name: "LR-F2",
            prefix: "multisource",
            description: "Logistic Regression được huấn luyện từ nhiều nguồn dữ liệu."
        },
        {
            name: "SVM-F2",
            prefix: "fusion",
            description: "Logistic Regression kết hợp đặc trưng URL và n-gram ký tự."
        }
    ];

    for (const model of extraModels) {
        const card = template.cloneNode(true);

        // Give every score, threshold, meter and status a unique ID.
        card.querySelectorAll("[id]").forEach(element => {
            if (element.id.startsWith("baseline-")) {
                element.id = model.prefix +
                    element.id.slice("baseline".length);
            } else {
                element.removeAttribute("id");
            }
        });

        if (card.id) {
            card.id = card.id.startsWith("baseline-")
                ? model.prefix + card.id.slice("baseline".length)
                : "";
        }

        const heading = card.querySelector("h3");

        if (!heading) {
            throw new Error("Model card heading missing.");
        }

        heading.textContent = model.name;
        const modelTag = card.querySelector(".model-tag");
        if (modelTag) {
            modelTag.textContent = "ADDITIONAL DETECTION MODEL";
        }

        const modelIcon = card.querySelector(".model-icon");
        if (modelIcon) {
            const modelNumbers = {
                xgb: "03",
                multisource: "04",
                fusion: "05"
            };
            modelIcon.textContent = modelNumbers[model.prefix];
        }

        const description = card.querySelector(
            ".model-description"
        );

        if (description) {
            description.textContent = model.description;
        }

        const label = card.querySelector(
            ".model-label, .model-badge, .model-type, .card-kicker"
        );

        if (label) {
            label.textContent = "ADDITIONAL MODEL";
        }

        for (const suffix of [
            "score", "threshold", "meter", "status"
        ]) {
            if (!card.querySelector(
                `#${model.prefix}-${suffix}`
            )) {
                throw new Error(
                    `Missing ${model.prefix}-${suffix}`
                );
            }
        }

        grid.appendChild(card);
    }
}

installExtraModelCards();

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


function applyThreatTheme(isDanger) {
    document.body.classList.toggle("danger-mode", isDanger);

    document.querySelectorAll("h1, h2, h3").forEach((heading) => {
        if (!heading.hasAttribute("data-crack-text")) {
            heading.setAttribute(
                "data-crack-text",
                heading.textContent.trim().replace(/\\s+/g, " ")
            );
        }

        heading.classList.toggle("cyber-cracked", isDanger);
    });
}

applyThreatTheme(false);

form.addEventListener("submit", async function (event) {
    event.preventDefault();

    resultsSection.hidden = true;
    applyThreatTheme(false);
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
        "Đang phân tích URL bằng 5 mô hình AI...",
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

        const suspiciousCount = validatedResults.filter(
            ({ result }) => result.suspicious
        ).length;

        const isDanger = suspiciousCount >= 2;
        applyThreatTheme(isDanger);

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


/* DIGITAL FORENSIC BINARY V3 */

(function () {
    document.querySelectorAll(".binary-rain").forEach(el => el.remove());

    const reducedMotion = window.matchMedia(
        "(prefers-reduced-motion: reduce)"
    ).matches;

    function createSide(side) {
        const container = document.createElement("div");
        container.className = "binary-rain binary-" + side;
        container.setAttribute("aria-hidden", "true");

        for (let column = 0; column < 3; column++) {
            const track = document.createElement("div");

            // Alternate each column, not the entire side.
            const up = (column + (side === "right" ? 1 : 0)) % 2 === 0;

            track.className = "binary-track " + (
                up ? "go-up" : "go-down"
            );

            const stream = document.createElement("div");
            stream.className = "binary-stream";

            // Fill the height with individual glowing digits.
            for (let row = 0; row < 52; row++) {
                const digit = document.createElement("span");

                digit.className = "binary-bit";
                digit.textContent = Math.random() < 0.5 ? "0" : "1";

                // Stagger flashes: digits don't light up together.
                digit.style.animationDelay =
                    `-${(Math.random() * 4.5).toFixed(2)}s`;

                digit.style.animationDuration =
                    `${(2.8 + Math.random() * 2.6).toFixed(2)}s`;

                stream.appendChild(digit);
            }

            track.appendChild(stream);
            container.appendChild(track);
        }

        document.body.appendChild(container);
    }

    createSide("left");
    createSide("right");

    // Occasionally change individual bits.
    if (!reducedMotion) {
        setInterval(() => {
            document.querySelectorAll(".binary-bit").forEach(bit => {
                if (Math.random() < 0.08) {
                    bit.textContent =
                        Math.random() < 0.5 ? "0" : "1";
                }
            });
        }, 1800);
    }
})();
