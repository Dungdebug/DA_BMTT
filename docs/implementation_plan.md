# Kế hoạch Hoàn thiện Hệ thống Phát hiện Mã độc Lai (Hybrid Malware Detector) & Đề xuất Biện pháp Khắc phục

Hệ thống được thiết kế theo đúng đề tài: **"Phát hiện file chứa mã độc dựa vào phương pháp lai kết hợp giữa phân tích tĩnh tại chỗ và tra cứu tri thức mối đe dọa đám mây"**, đồng thời tích hợp **AI phân tích chuyên sâu, phát hiện file lạ/Zero-day** và **tự động đề xuất biện pháp khắc phục, xử lý sự cố**.

---

## 1. Mục tiêu và Điểm mới của Hệ thống

1. **Phân tích tĩnh chuyên sâu (Deep Static Analysis)**:
   - Bóc tách PE Header, Entropy từng section, phát hiện packer/crypter (.upx, .themida, .aspack,...).
   - Phát hiện các Windows API nhạy cảm thường dùng trong tấn công mạng (Process Injection, Memory Tampering, Persistence, Evasion, C2 Communication).
   - Tính toán đầy đủ mã băm (MD5, SHA-1, SHA-256, Imphash).

2. **Động cơ AI phát hiện mã độc & Nhận diện "File lạ" (AI & Anomaly / Zero-Day Engine)**:
   - Nâng cấp mô hình Machine Learning (`RandomForestClassifier` + `GradientBoosting` / `Anomaly Detection`) với bộ dữ liệu đặc trưng chuẩn hóa thay cho 6 mẫu mock sơ sài.
   - Nhận diện 3 trạng thái rõ ràng:
     - 🟢 **BENIGN (File sạch/An toàn)**
     - 🟡 **SUSPICIOUS / UNKNOWN (File lạ / Nghi vấn mã độc mới / Zero-Day)**
     - 🔴 **MALICIOUS (Mã độc đã xác thực)**
   - Giải thích lý do AI đưa ra kết luận (Explainable AI - XAI: chỉ rõ các đặc trưng đáng ngờ như Entropy cao, Import API nguy hiểm, Section dị thường).

3. **Tra cứu tri thức đám mây (Cloud Threat Intelligence)**:
   - Tra cứu trên VirusTotal API v3 theo mã băm SHA-256.
   - Lấy chi tiết số hãng bảo mật nhận diện, phân loại mối đe dọa (Trojan, Ransomware, Worm, Backdoor, Adware...).
   - Cơ chế Fallback / Mock Cache thông minh khi người dùng chưa có API key hoặc khi quét offline.

4. **Động cơ Phán quyết Lai (Hybrid Decision Engine)**:
   - Kết hợp 3 nguồn: Phân tích tĩnh + AI cục bộ + Đám mây theo ma trận rủi ro động.
   - Tính toán chỉ số nguy cơ tổng thể (Overall Risk Score: 0.0 - 100.0%).

5. **Mô-đun Đề xuất Biện pháp Khắc phục (AI Remediation & Incident Response)**:
   - Dựa trên loại mã độc và hành vi phát hiện, tự động đưa ra:
     - **Mức độ khẩn cấp (Severity level: Low / Medium / High / Critical)**.
     - **Biện pháp khẩn cấp (Immediate containment)**: Cách ly file vào vùng an toàn (Quarantine), hủy tiến trình (Kill process).
     - **Kiểm tra lây nhiễm & duy trì (Persistence check)**: Rà soát khóa Registry Run/RunOnce, Startup folder, Scheduled Tasks, Services.
     - **Khắc phục & Gia cố (Hardening & Recovery)**: Chặn hash trên EDR/Firewall, hướng dẫn phục hồi dữ liệu.
     - **Tự động sinh kịch bản khắc phục (Auto-generated Remediation Script)**: Tạo script PowerShell (.ps1) để người quản trị có thể chạy xử lý tức thì chỉ với 1 click.

6. **Giao diện Web Dashboard Trực quan (Modern Web GUI)**:
   - Xây dựng giao diện Web Dashboard chạy trên trình duyệt (sử dụng Flask/Python Backend + HTML5/CSS3/JS hiện đại):
     - Kéo thả file để quét trực quan.
     - Hỗ trợ các nút **"Mẫu thử nghiệm Demo"** (Demo Benign, Demo Ransomware, Demo Packed/Zero-day) để báo cáo/thuyết minh đồ án dễ dàng ngay cả khi không có sẵn mẫu virus thật.
     - Biểu đồ trực quan: Đồng hồ đo rủi ro (Risk Gauge), thanh đo Entropy từng Section, danh sách API đáng ngờ.
     - Hộp thoại giải thích AI và Tab Biện pháp khắc phục.
     - Xuất báo cáo kết quả quét định dạng JSON / HTML Report chuyên nghiệp để nộp đồ án.

---

## 2. Kiến trúc & Các thành phần cần cập nhật

### [MODIFY] [static_analyzer.py](file:///c:/laragon/laragon/www/DA_BMTT/static_analyzer.py)
- Bổ sung trích xuất mã băm SHA-1 và `imphash` (Import Hash).
- Mở rộng phân tích bảng Import để phát hiện các nhóm API nguy hiểm (Memory Injection, Network C2, Persistence, Anti-Debug).
- Tính toán chi tiết cấu trúc từng section (Raw Size vs Virtual Size để phát hiện packing).

### [MODIFY] [ai_engine.py](file:///c:/laragon/laragon/www/DA_BMTT/ai_engine.py)
- Mở rộng vector đặc trưng từ 7 lên 12 đặc trưng toàn diện.
- Huấn luyện mô hình chuẩn hóa với bộ dữ liệu phân bổ chuẩn (chuẩn hóa MinMax / StandardScaler).
- Bổ sung hàm giải thích đặc trưng bất thường (Explainable AI - XAI: chỉ rõ các lý do AI cảnh báo).
- Hỗ trợ phát hiện phân loại: `BENIGN`, `SUSPICIOUS_UNKNOWN` (File lạ), `MALICIOUS`.

### [MODIFY] [cloud_threat_intel.py](file:///c:/laragon/laragon/www/DA_BMTT/cloud_threat_intel.py)
- Tối ưu hóa xử lý lỗi, thêm cache kết quả băm để tiết kiệm lượt gọi API.
- Trích xuất tên chủng loại mã độc (Trojan, Ransomware, Stealer...) từ các hãng AV hàng đầu (Kaspersky, Microsoft, CrowdStrike...).
- Hỗ trợ chế độ Demo/Mock Threat Intel giúp minh họa mượt mà khi bảo vệ đồ án.

### [NEW] `remediation_engine.py`
- Mô đun chuyên trách phân tích và đưa ra giải pháp khắc phục (Remediation Playbook).
- Sinh hướng dẫn chi tiết theo từng loại mối đe dọa (Ransomware, Spyware, Worm, Trojan, Zero-day).
- Tự động sinh mã lệnh PowerShell (`remediate.ps1`) để cách ly file, diệt process và dọn dẹp persistence.

### [MODIFY] [hybrid_detector.py](file:///c:/laragon/laragon/www/DA_BMTT/hybrid_detector.py)
- Khắc phục lỗi thiếu `import os`.
- Tích hợp 4 động cơ: `StaticAnalyzer` + `AIEngine` + `CloudThreatIntel` + `RemediationEngine`.
- Bổ sung logic phân loại 3 mức: An toàn, File lạ/Zero-day, Mã độc.

### [NEW] `app.py` & Giao diện Web Dashboard (`templates/index.html`, `static/style.css`, `static/app.js`)
- Backend máy chủ Web nhẹ (sử dụng Flask hoặc module HTTP API).
- Giao diện Dark Mode phong cách An toàn thông tin / Cyber Security hiện đại, trực quan, hỗ trợ kéo thả file, xem biểu đồ và tải báo cáo.

---

## 3. Kế hoạch Kiểm tra & Xác minh (Verification Plan)

### Kiểm tra tự động & Chạy thử nghiệm
1. Cài đặt các thư viện cần thiết (`flask` nếu làm Web Dashboard).
2. Chạy test kịch bản phát hiện:
   - File sạch thông thường (ví dụ: `notepad.exe` hoặc file do hệ thống tạo).
   - File giả lập mã độc nén/packed (Entropy cao, packed sections, API nhạy cảm).
   - File lạ/Zero-day (Chưa có trên Cloud, AI phát hiện hành vi khả nghi).
3. Kiểm tra tính chính xác của:
   - Trích xuất đặc trưng tĩnh & Shannon entropy.
   - Kết quả phân loại AI và độ tự tin (Confidence).
   - Nội dung khuyến nghị khắc phục và script PowerShell được sinh ra.
4. Kiểm thử giao diện Web Dashboard trên trình duyệt.
