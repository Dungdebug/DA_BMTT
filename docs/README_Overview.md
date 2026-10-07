# Tổng quan Dự án: Hệ thống Phát hiện Mã độc Lai (Hybrid Malware Detector)

Dự án này là một hệ thống phát hiện mã độc chuyên sâu, kết hợp giữa **Phân tích tĩnh (Static Analysis)**, **Học máy cục bộ (Local AI)** và **Tri thức đám mây (Cloud Threat Intelligence)**. Hệ thống được thiết kế theo nguyên tắc lọc phân tầng (Tiered Filtering), rất phù hợp cho Đồ án tốt nghiệp chuyên ngành An toàn thông tin.

---

## 🧠 1. Các thành phần lõi trong Code (Core Modules)

Mã nguồn được chia thành các module (`.py`) biệt lập, mỗi file đóng một vai trò riêng trong "dây chuyền" quét mã độc:

### 🔍 `static_analyzer.py` (Chuyên gia giải phẫu)
*   **Nhiệm vụ:** Đọc file `.exe` mà không cần chạy nó.
*   **Nội dung:** Trích xuất 12 đặc trưng toán học của file như: độ hỗn loạn (Entropy), đếm số lượng hàm API nguy hiểm (tiêm nhiễm, né tránh Sandbox), kiểm tra cấu trúc nén bất thường, và lấy mã `Imphash`.
*   **Đầu ra:** Trả về một mảng 12 con số (Vector đặc trưng) để đưa cho AI chấm điểm.

### 🤖 `ai_engine.py` (Bộ não Học máy - AI)
*   **Nhiệm vụ:** Chuyên gia AI chấm điểm file dựa trên kinh nghiệm.
*   **Nội dung:** Sử dụng thuật toán **Random Forest**. Hệ thống nạp file dữ liệu Kaggle (`dataset_malwares.csv` gồm gần 20.000 mẫu) để huấn luyện. Khi nhận được vector từ `static_analyzer`, nó dự đoán xác suất mã độc.
*   **XAI (Explainable AI):** Có khả năng giải thích *tại sao* lại nghi ngờ file đó bằng các luận điểm rõ ràng.

### ☁️ `cloud_threat_intel.py` (Tình báo Đám mây - CTI)
*   **Nhiệm vụ:** Hỏi "cộng đồng mạng" xem file này có tiếng xấu không.
*   **Nội dung:** Tự động kết nối tới API của **VirusTotal**. Nó lấy mã Hash (SHA-256) hoặc Imphash mang lên mạng tra cứu xem có bao nhiêu phần mềm diệt virus toàn cầu đã phát hiện file này.

### ⚖️ `hybrid_detector.py` (Thẩm phán tối cao - Decision Engine)
*   **Nhiệm vụ:** Trái tim của toàn hệ thống. Tổng hợp kết quả từ 3 "chuyên gia" trên.
*   **Nội dung:** Áp dụng công thức toán học có trọng số:
    `Điểm Rủi Ro = (25% x Điểm Tĩnh) + (35% x Điểm AI) + (40% x Điểm Đám mây)`
    *Đặc biệt, hệ thống có cơ chế Trọng số động (Dynamic Weighting): Tự động dồn trọng số sang AI và Static nếu file là mã độc mới tinh (Zero-day) hoặc máy tính mất mạng.*

### 🛡️ `remediation_engine.py` (Bác sĩ kê đơn)
*   **Nhiệm vụ:** Đưa ra kịch bản ứng phó (Playbook).
*   **Nội dung:** Tự động sinh ra các bước khuyến nghị cho người dùng (cách ly file, chặn mạng, dọn Registry...) nếu phát hiện mã độc.

### 🌐 `app.py` (Giao diện Web)
*   **Nhiệm vụ:** Là cầu nối tương tác với người dùng qua trình duyệt.
*   **Nội dung:** Máy chủ web (Flask) cho phép người dùng Upload file và hiển thị bảng kết quả quét trực quan, đẹp mắt.

---

## ⚙️ 2. Hướng dẫn sử dụng toàn tập

Hệ thống có 2 luồng sử dụng chính:

### Luồng 1: Dành cho Người dùng (Sử dụng Web để quét file)
1. Mở Terminal tại thư mục dự án và gõ `.\run_app.bat` (hoặc `.\.venv\Scripts\python.exe app.py`).
2. Mở trình duyệt truy cập vào **http://127.0.0.1:5000**.
3. Upload một file `.exe` bất kỳ vào (Hệ thống sẽ tự động chạy qua toàn bộ 4 Tầng lọc phân tích).
4. Xem bảng báo cáo kết quả (Điểm rủi ro, phân loại, lý do từ AI, kết quả từ Cloud và Hướng dẫn khắc phục).

### Luồng 2: Dành cho Kỹ sư / Sinh viên (Huấn luyện lại AI)
Khi muốn tinh chỉnh để AI thông minh hơn:
1. Mở file `train_eval.py`.
2. Tinh chỉnh các tham số thuật toán ở dòng 37 (vd: `n_estimators`, `max_depth`).
3. Mở Terminal gõ `.\.venv\Scripts\python.exe train_eval.py`.
4. Xem bảng kết quả in ra % điểm độ chính xác (Accuracy). Hệ thống sẽ tự động cập nhật "não bộ" mới vào file `malware_rf_model.pkl`.

> 💡 **Điểm nhấn Báo cáo Đồ án:**
> Sức mạnh cốt lõi của hệ thống nằm ở file `hybrid_detector.py`. Việc kết hợp hài hòa giữa **AI cục bộ** (bắt mã độc Zero-day offline) và **CTI Đám mây** (bắt mã độc đã biết online), cùng với công thức **Trọng số động (Dynamic Weighting)** là điểm sáng giá nhất của toàn bộ giải pháp kiến trúc này!
