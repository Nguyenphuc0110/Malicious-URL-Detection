# NOTE QUÁ TRÌNH XỬ LÝ DỮ LIỆU A1–A5

## Mục đích
Ghi lại các thay đổi, quyết định và kết quả thực tế trong quá trình Phúc thực hiện A1–A5 để cả nhóm biết dữ liệu hiện tại khác gì so với kế hoạch ban đầu.

## A1 – Source A

### Kế hoạch ban đầu
Dùng ISCX-URL2016 raw URL với 5 nhóm: benign, defacement, phishing, malware, spam.

### Vấn đề
Trang CIC/UNB hiện chủ yếu cho các file feature đã trích xuất sẵn như `All.csv`, `Defacement.csv`, `Malware.csv`, `Phishing.csv`, `Spam.csv`. Các file này không còn URL thô đầy đủ nên không phù hợp cho normalize URL, registered domain, lexical features, char n-gram và split theo domain.

### Thay đổi
Thay Source A bằng **Malicious URLs Dataset (Kaggle – sid321axn)**, file `malicious_phish.csv`.

Dataset hiện có 4 class:
- benign: 428,103
- defacement: 96,457
- phishing: 94,111
- malware: 32,520

Tổng ban đầu: **651,191 URL**.

**Lưu ý:** Dataset này là bộ tổng hợp từ nhiều nguồn, trong đó có dữ liệu có nguồn gốc từ ISCX-URL2016, nhưng không được gọi là ISCX-URL2016 gốc trong report. Source A hiện không có class `spam`.

## A2 – Source B

### PhiUSIIL
Chỉ lấy `URL` và `label`.

Mapping:
- `1 -> benign`
- `0 -> phishing`

Sau xử lý:
- benign: 134,850
- phishing: 100,945

Output: `data/raw/source_b_phiusiil.csv`

### Phishing 2025
File phân công ghi “phishing 2025 [6]” nhưng không có link/tên dataset đầy đủ. Đã thay bằng **LegitPhish 2025**, file gốc `url_features_extracted1.csv`.

Chỉ giữ:
- `URL`
- `ClassLabel`

Mapping:
- `1 -> benign`
- `0 -> phishing`

Có 1 dòng thiếu `ClassLabel`, đã loại thay vì tự đoán nhãn.

Sau xử lý:
- phishing: 63,678
- benign: 37,540
- tổng: 101,218

Duplicate URL phát hiện: 346, chưa xóa ở A2 để xử lý tại A5.

Output: `data/raw/source_b_2025.csv`

### Overlap benign
Sau lowercase + strip:
- Source A vs Source B 2025: **0**
- Source A vs PhiUSIIL: **0**

## A3 – Source C

### OpenPhish
- file: `data/raw/source_c/openphish/openphish.txt`
- số URL: 300
- label: phishing

### PhishTank
- file: `data/raw/source_c/phishtank/online-valid.csv`
- số URL: 77,519
- label: phishing

### Tranco
- file: `data/raw/source_c/tranco/top-1m.csv`
- số domain: 1,000,000
- chuyển thành URL dạng `https://domain.com`
- label: benign

Outputs:
- `data/processed/source_c_malicious.csv`
- `data/processed/source_c_benign.csv`

Tổng Source C:
- malicious: 77,819
- benign: 1,000,000

## A4 – Normalize URL

Quy tắc:
- trim whitespace
- thêm scheme nếu thiếu
- lowercase scheme/hostname
- giữ path/query
- bỏ fragment
- bỏ default port 80/443
- giữ non-default port

Kết quả:
- Source A: 651,191 -> fail 33 -> còn **651,158**
- Source B: 337,013 -> fail 0
- Source C: 1,077,819 -> fail 0

Outputs:
- `data/processed/source_a_normalized.csv`
- `data/processed/source_b_normalized.csv`
- `data/processed/source_c_normalized.csv`

Logs:
- `outputs/logs/source_a_normalization_failed.csv`
- `outputs/logs/source_b_normalization_failed.csv`
- `outputs/logs/source_c_normalization_failed.csv`

## A5 – Dedup + Registered Domain + Split

A5 hiện split Source A để tạo train/validation/test_A.

### Conflicting labels
- conflicting normalized URLs: 3,940
- rows involved: 7,907
- đã loại toàn bộ các dòng conflict thay vì tự chọn label

Log:
- `outputs/logs/source_a_conflicting_labels.csv`

### Deduplicate
- rows before dedup: 643,251
- duplicate removed: 10,216
- rows after dedup: **633,035**

### Registered domain
- invalid domain: 0
- unique registered domains: **154,559**

### Split theo registered domain
Không chia ngẫu nhiên từng URL.

#### Train
- 447,075 URL
- 108,191 domains

Class distribution:
- benign: 296,703
- defacement: 66,385
- phishing: 65,590
- malware: 18,397

#### Validation
- 104,798 URL
- 23,184 domains

Class distribution:
- benign: 75,358
- defacement: 15,039
- phishing: 11,880
- malware: 2,521

#### Test A
- 81,162 URL
- 23,184 domains

Class distribution:
- benign: 51,992
- defacement: 13,884
- phishing: 12,561
- malware: 2,725

### Vì sao số URL không đúng chính xác 70/15/15?
Split theo **registered domain**, không theo từng URL. Một domain có thể có nhiều URL nên tỷ lệ số domain gần 70/15/15 nhưng số URL có thể lệch.

### Leakage check
Domain overlap:
- Train ∩ Val = 0
- Train ∩ Test = 0
- Val ∩ Test = 0

URL overlap:
- Train ∩ Val = 0
- Train ∩ Test = 0
- Val ∩ Test = 0

=> Không phát hiện domain leakage hoặc URL leakage.

Outputs:
- `data/processed/source_a_dedup.csv`
- `data/processed/train.csv`
- `data/processed/val.csv`
- `data/processed/test_A.csv`
- `outputs/tables/source_a_split_summary.csv`

## Tóm tắt thay đổi so với kế hoạch

| Hạng mục | Kế hoạch ban đầu | Thực tế |
|---|---|---|
| A1 | ISCX-URL2016 raw 5 class | Dùng Kaggle Malicious URLs Dataset, 4 class |
| Spam | Có | Không có trong Source A hiện tại |
| A2 phishing 2025 | Bộ [6] của nhóm | Thay bằng LegitPhish 2025 |
| A2 PhiUSIIL | URL + label | Đã làm |
| A3 | OpenPhish + PhishTank + Tranco | Đã làm |
| A4 | Normalize A/B/C | Đã hoàn thành |
| A5 | Dedup + domain split | Đã hoàn thành trên Source A |
| Split | 70/15/15 | Theo domain; tỷ lệ URL không tuyệt đối 70/15/15 |
| Leakage | Không overlap | Domain overlap = 0, URL overlap = 0 |

## Phần còn phụ thuộc thành viên khác

### A6
Chưa hoàn chỉnh vì cần feature code F1/F2 từ Dũng để chạy trên Source B/C.

### A7
Chưa làm vì cần prediction/model output từ Hiếu để phân tích benign false positives.

### A8
Có thể viết trước phần Dataset, EDA, preprocessing, dedup và split strategy. Phần error analysis bổ sung sau A7.

## Lưu ý cho nhóm
1. Raw/processed dataset lớn không nằm trên GitHub vì đã được `.gitignore`.
2. GitHub hiện chứa code, README, log và bảng nhỏ.
3. Dataset lớn nên chia sẻ qua Google Drive/OneDrive.
4. Khi viết report phải ghi rõ Source A đã thay đổi so với proposal.
5. Không gọi Source A hiện tại là “ISCX-URL2016 gốc”.
6. Dũng/Hiếu nên giữ nguyên `train.csv`, `val.csv`, `test_A.csv` để không phá split chống leakage.
