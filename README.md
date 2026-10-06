# Hệ Thống Phát Hiện Mã Độc Lai (Hybrid Malware Detector) & Đề Xuất Biện Pháp Khắc Phục

> **Đồ án môn học:** Bảo Mật Thông Tin (DA_BMTT)  
> **Đề tài:** *"Phát hiện file chứa mã độc dựa vào phương pháp lai kết hợp giữa phân tích tĩnh tại chỗ và tra cứu tri thức mối đe dọa đám mây"*  
> **Tác giả:** Sinh viên thực hiện đồ án DA_BMTT  
> **Công nghệ:** Python 3.10+, Flask, Scikit-learn (Machine Learning), Pefile, VirusTotal API v3, PowerShell Scripting, HTML5/CSS3/Vanilla JS.

---

## 📌 Mục Lục
1. [Giới Thiệu Tổng Quan & Điểm Mới](#1-giới-thiệu-tổng-quan--điểm-mới)
2. [Kiến Trúc Toàn Diện Của Hệ Thống](#2-kiến-trúc-toàn-diện-của-hệ-thống)
3. [Chi Tiết Các Mô-đun Trong Mã Nguồn](#3-chi-tiết-các-mô-đun-trong-mã-nguồn)
   - [3.1. Phân Tích Tĩnh Tại Chỗ (static_analyzer.py)](#31-phân-tích-tĩnh-tại-chỗ-static_analyzerpy)
   - [3.2. Động Cơ Trí Tuệ Nhân Tạo & XAI (ai_engine.py)](#32-động-cơ-trí-tuệ-nhân-tạo--xai-ai_enginepy)
   - [3.3. Tra Cứu Tri Thức Đám Mây (cloud_threat_intel.py)](#33-tra-cứu-tri-thức-đám-mây-cloud_threat_intelpy)
   - [3.4. Động Cơ Phán Quyết Lai (hybrid_detector.py)](#34-động-cơ-phán-quyết-lai-hybrid_detectorpy)
   - [3.5. Ứng Phó Sự Cố & Sinh Script Khắc Phục (remediation_engine.py)](#35-ứng-phó-sự-cố--sinh-script-khắc-phục-remediation_enginepy)
   - [3.6. Giao Diện Web Dashboard (app.py & Frontend)](#36-giao-diện-web-dashboard-apppy--frontend)
4. [Cấu Trúc Thư Mục Dự Án](#4-cấu-trúc-thư-mục-dự-án)
5. [Hướng Dẫn Triển Khai & Khởi Chạy](#5-hướng-dẫn-triển-khai--khởi-chạy)
   - [Cách 1: Khởi chạy 1-Click bằng run_app.bat](#cách-1-khởi-chạy-1-click-bằng-run_appbat-khuyên-dùng)
   - [Cách 2: Khởi chạy Web Server bằng PowerShell](#cách-2-khởi-chạy-web-server-bằng-powershell--cmd)
   - [Cách 3: Chạy Quét Nhanh Bằng Dòng Lệnh (CLI)](#cách-3-chạy-quét-nhanh-bằng-dòng-lệnh-cli)
6. [Kịch Bản Thuyết Minh & Trình Diễn Đồ Án (Demo Walkthrough)](#6-kịch-bản-thuyết-minh--trình-diễn-đồ-án-demo-walkthrough)
7. [Các Thư Viện Sử Dụng & Yêu Cầu Môi Trường](#7-các-thư-viện-sử-dụng--yêu-cầu-môi-trường)

---

## 1. Giới Thiệu Tổng Quan & Điểm Mới

Trong bối cảnh an toàn thông tin hiện đại, các phương pháp bảo vệ truyền thống gặp nhiều thách thức:
- **Phương pháp truyền thống dựa vào chữ ký băm (Hash Signature)**: Rất nhanh và chính xác với mã độc cũ, nhưng **vô hiệu hóa hoàn toàn** trước biến thể mới hoặc mã độc **Zero-Day** (chỉ cần đổi 1 byte là mã băm thay đổi hoàn toàn).
- **Phương pháp phân tích động (Sandbox)**: Tốn nhiều tài nguyên, thời gian chờ lâu và dễ bị mã độc nhận diện môi trường ảo để lẩn tránh (Anti-Sandbox / Evasion).

### Đóng góp và điểm mới của đồ án:
1. **Phương pháp tiếp cận Lai (Hybrid)**: Kết hợp tốc độ và tri thức cộng đồng của mạng lưới đám mây (**VirusTotal Cloud**) với khả năng phân tích nhị phân sâu tại chỗ (**Static PE Analysis + Local Machine Learning**).
2. **Khả năng bắt Mã độc Mới / Zero-Day**: Khi tệp tin chưa từng xuất hiện trên đám mây (VirusTotal trả về 404), động cơ AI tại chỗ sẽ tự động kích hoạt chế độ Heuristics để bóc tách hành vi mã độc (độ hỗn loạn Entropy cao, packer giấu mã, Windows API can thiệp bộ nhớ nhạy cảm).
3. **Trí tuệ nhân tạo có thể giải thích (Explainable AI - XAI)**: Không chỉ trả ra con số phần trăm mù mờ, hệ thống liệt kê cụ thể các đặc trưng cấu trúc khiến tệp bị đánh giá là rủi ro.
4. **Tự động hóa ứng phó sự cố (Remediation & Incident Response Playbook)**: Hệ thống tự động phân loại mức độ nghiêm trọng (Critical/High/Medium/Info) và **sinh kịch bản PowerShell (.ps1)** giúp quản trị viên cô lập file, diệt tiến trình độc và dọn sạch mã độc duy trì khởi động chỉ với 1 cú click.

---

## 2. Kiến Trúc Toàn Diện Của Hệ Thống

```
+-----------------------------------------------------------------------------------------+
|                                TỆP MỤC TIÊU (.EXE / .DLL)                              |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| 1. BÓC TÁCH CẤU TRÚC TĨNH (static_analyzer.py)                                          |
| - Tính toán MD5, SHA-1, SHA-256, Imphash                                                |
| - Đo Shannon Entropy toàn file & từng Section (0.0 - 8.0)                                |
| - Nhận diện Section nén/packer độc hại (.upx, .themida, .aspack...)                     |
| - Quét bảng Import Table nhận diện Windows API nhạy cảm (Injection, Persistence, C2...)  |
| - Phát hiện bất thường kích thước RAM vs Đĩa (VirtualSize >> RawData)                   |
+-----------------------------------------------------------------------------------------+
                        /                                        \
                       v                                          v
+----------------------------------------+   +--------------------------------------------+
| 2. ĐỘNG CƠ HỌC MÁY CỤC BỘ              |   | 3. TRI THỨC MỐI ĐE DỌA ĐÁM MÂY             |
|    (ai_engine.py & .pkl)               |   |    (cloud_threat_intel.py)                 |
| - Vector 12 đặc trưng số hóa           |   | - Tra cứu SHA-256 trên VirusTotal API v3   |
| - Mô hình Random Forest (100 Trees)    |   | - Cơ chế Cache cục bộ (vt_cache.json)      |
| - Chuẩn hóa dữ liệu với StandardScaler |   | - Bộ chữ ký mẫu Demo (WannaCry, Emotet)    |
| - XAI: Giải trình đặc trưng rủi ro     |   | - Thống kê số lượng hãng AV phát hiện      |
| - Phân loại: Benign / Suspicious / Mal |   | - Xử lý thông minh khi Cloud 404 (Zero-Day)|
+----------------------------------------+   +--------------------------------------------+
                        \                                        /
                         v                                      v
+-----------------------------------------------------------------------------------------+
| 4. ĐỘNG CƠ PHÁN QUYẾT LAI (hybrid_detector.py)                                          |
| - Phân tích ma trận trọng số rủi ro đa nguồn                                            |
| - Điểm rủi ro tổng hợp (Overall Risk Score: 0% - 100%)                                  |
| - Kết luận cuối cùng: BENIGN / SUSPICIOUS_UNKNOWN / MALICIOUS                           |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| 5. ĐỀ XUẤT BIỆN PHÁP KHẮC PHỤC (remediation_engine.py)                                   |
| - Playbook ứng phó 4 giai đoạn: Cô lập -> Điều tra -> Tiễu trừ -> Gia cố                |
| - Tự động sinh mã kịch bản PowerShell (.ps1) cách ly và dọn dẹp hệ thống                |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| 6. TRÌNH DIỄN KẾT QUẢ                                                                   |
| - Web Dashboard hiện đại (Flask, Chart Gauge, Section Bars, XAI Badges)                  |
| - Chế độ dòng lệnh CLI xuất cấu trúc JSON chuẩn                                         |
+-----------------------------------------------------------------------------------------+
```

---

## 3. Chi Tiết Các Mô-đun Trong Mã Nguồn

### 3.1. Phân Tích Tĩnh Tại Chỗ (`static_analyzer.py`)
Mô-đun chịu trách nhiệm mổ xẻ tệp nhị phân mà **không cần thực thi tệp**, đảm bảo an toàn tuyệt đối cho hệ thống phân tích.

- **Tính toán hàm băm**: `MD5`, `SHA-1`, `SHA-256`, và đặc biệt là `imphash` (Import Hash - băm thứ tự các hàm API import để nhận diện các biến thể virus cùng một họ mã nguồn).
- **Shannon Entropy**:
  $$\text{Entropy} = -\sum_{i=0}^{255} p(x_i) \log_2 p(x_i)$$
  Giá trị từ $0.0$ đến $8.0$. File thực thi bình thường thường có entropy từ $4.5 - 6.5$. Nếu entropy $> 7.2$, tệp có dấu hiệu bị mã hóa hoặc nén (obfuscated/packed) để giấu mã độc.
- **Phát hiện Packer/Crypter**: Quét các tên section đặc trưng: `.upx`, `upx0`, `upx1`, `.aspack`, `.mpress`, `.themida`, `.vmp`, `.enigma`...
- **Phát hiện dị thường kích thước bộ nhớ (Size Anomaly)**: So sánh `VirtualSize` (kích thước chiếm trong RAM) và `SizeOfRawData` (kích thước trên ổ đĩa). Nếu kích thước trong RAM lớn gấp nhiều lần trên đĩa, đây là dấu hiệu của kỹ thuật unpacked trực tiếp vào bộ nhớ.
- **Phân loại 6 nhóm Windows API nguy hiểm**:
  1. *Injection (Tiêm mã)*: `VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`...
  2. *Persistence (Duy trì khởi động)*: `RegSetValueEx`, `RegCreateKeyEx`, `CreateService`, `OpenSCManager`...
  3. *Evasion (Lẩn tránh/Anti-Debug)*: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `FindWindow`, `Sleep`, `BlockInput`...
  4. *Network C2 (Kết nối điều khiển)*: `URLDownloadToFile`, `InternetOpen`, `HttpSendRequest`, `WSAStartup`, `connect`...
  5. *Execution (Thực thi lệnh ngầm)*: `WinExec`, `ShellExecute`, `CreateProcess`...
  6. *Spying (Theo dõi phím/dữ liệu)*: `GetAsyncKeyState`, `GetKeyState`, `SetWindowsHookEx`, `GetClipboardData`...

- **Vector 12 Đặc Trưng Đầu Vào Cho AI**:
  `[file_size, num_sections, overall_entropy, max_sec_entropy, num_imported_dlls, num_imported_funcs, has_suspicious_section, size_anomaly_count, count_injection_apis, count_persistence_apis, count_evasion_apis, count_network_apis]`

---

### 3.2. Động Cơ Trí Tuệ Nhân Tạo & XAI (`ai_engine.py`)
Mô-đun học máy được thiết kế để phát hiện các mối đe dọa tiềm ẩn dựa trên các quy luật phi tuyến tính giữa 12 đặc trưng tĩnh.

- **Mô hình học máy**: **Random Forest Classifier** (`scikit-learn`):
  - Gồm 100 cây quyết định (`n_estimators=100`, `max_depth=8`).
  - Sử dụng `StandardScaler` trong `Pipeline` chuẩn hóa để loại bỏ sự sai lệch về đơn vị đo giữa kích thước file và số lượng hàm API.
  - Tệp mô hình huấn luyện sẵn được lưu trữ tuần tự hóa tại `malware_rf_model.pkl`.
- **Phân loại 3 mức độ rõ ràng**:
  - 🟢 **`BENIGN`**: File an toàn, cấu trúc chuẩn mực.
  - 🟡 **`SUSPICIOUS_UNKNOWN`**: File lạ, nghi vấn bất thường hoặc biến thể Zero-Day chưa từng thấy.
  - 🔴 **`MALICIOUS`**: Tệp mang các đặc trưng nguy hiểm đã được định danh.
- **Explainable AI (XAI)**:
  Hàm `explain_features()` tự động bóc tách các bất thường và xuất danh sách các cảnh báo trực quan kèm mức độ nghiêm trọng:
  - *High Entropy / Obfuscation*: Cảnh báo file bị đóng gói nhằm giấu payload độc.
  - *Process Injection*: Cảnh báo các API can thiệp vùng nhớ tiến trình khác.
  - *Persistence Mechanism*: Cảnh báo các API tự ghi vào khóa khởi động Windows.
  - *Hidden Imports*: Cảnh báo bảng Import bị làm rỗng bất thường.

---

### 3.3. Tra Cứu Tri Thức Đám Mây (`cloud_threat_intel.py`)
Mô-đun kết nối với mạng lưới tình báo mối đe dọa toàn cầu thông qua **VirusTotal API v3**.

- **Endpoint sử dụng**: `GET https://www.virustotal.com/api/v3/files/{sha256}`.
- **Xử lý đa tầng (Multi-tier Strategy)**:
  1. *Tầng 1 - Cache Cục Bộ (`vt_cache.json`)*: Kiểm tra mã băm đã từng quét trước đó chưa. Nếu có, trả về kết quả ngay lập tức mà không tiêu tốn lượt gọi API.
  2. *Tầng 2 - Bộ Chữ Ký Demo*: Tích hợp sẵn mã băm của các chủng mã độc lịch sử (*WannaCry*, *Emotet*) để trình diễn thuyết minh mượt mà ngay cả khi không có kết nối Internet hoặc tài khoản API hết hạn.
  3. *Tầng 3 - Live API VirusTotal*: Gửi request kèm `x-apikey`. Bóc tách số lượng AV phát hiện (`positives/total`), nhãn phân loại chủng loại (`threat_classification`), và kết quả từ các hãng bảo mật danh tiếng (Microsoft, Kaspersky, CrowdStrike, Sophos...).
  4. *Tầng 4 - Xử lý Zero-Day (HTTP 404)*: Khi file chưa từng xuất hiện trên VirusTotal, hệ thống thông minh gắn nhãn là *Tệp hoàn toàn mới (Zero-Day Candidate)* thay vì báo lỗi, sau đó chuyển giao cho AI tại chỗ thẩm định.

---

### 3.4. Động Cơ Phán Quyết Lai (`hybrid_detector.py`)
Nơi tích hợp dữ liệu từ cả 3 nguồn: Phân tích tĩnh + AI tại chỗ + Đám mây để đưa ra quyết định cuối cùng dựa trên ma trận logic:

1. **Trường hợp 1 - Đồng thuận đám mây mạnh (Cloud Consensus)**:
   - Điều kiện: Đám mây có $\ge 5$ hãng bảo mật cảnh báo độc hại.
   - Kết luận: `MALICIOUS` (Điểm rủi ro $\ge 85\%$).
2. **Trường hợp 2 - Đám mây nghi vấn nhẹ (1 đến 4 hãng)**:
   - Kết hợp kiểm chứng chéo với AI tại chỗ. Nếu AI cũng phát hiện hành vi độc $\rightarrow$ `MALICIOUS`. Nếu AI đánh giá rủi ro thấp $\rightarrow$ đưa vào diện giám sát `SUSPICIOUS_UNKNOWN`.
3. **Trường hợp 3 - File lạ / Zero-Day / Chế độ Offline (Không có API Key)**:
   - Dựa trên phán đoán của mô hình AI phân tích tĩnh tại chỗ để phân định: `BENIGN`, `SUSPICIOUS_UNKNOWN`, hoặc `MALICIOUS`.
4. **Trường hợp 4 - Ma trận trọng số cân bằng**:
   - $\text{Risk Score} = 0.6 \times \text{Cloud Score} + 0.4 \times \text{AI Confidence}$.

---

### 3.5. Ứng Phó Sự Cố & Sinh Script Khắc Phục (`remediation_engine.py`)
Điểm độc đáo của đề tài là không dừng lại ở việc phát hiện mà còn đề xuất quy trình xử lý sự cố chuẩn An toàn thông tin:

- **Phân cấp mức độ (Severity)**: `CRITICAL` (Ransomware/Rủi ro $\ge 85\%$), `HIGH`, `MEDIUM`, `INFO`.
- **Quy trình 4 giai đoạn chuẩn Incident Response**:
  1. *Hành động khẩn cấp (Immediate Containment)*: Cách ly tệp vào vùng an toàn, buộc dừng tiến trình độc, ngắt kết nối mạng tạm thời nếu có hành vi C2/Ransomware.
  2. *Điều tra nguồn gốc (Investigation)*: Rà soát các điểm duy trì (Persistence) tại Registry `Run`/`RunOnce`, thư mục `Startup`, Scheduled Tasks, Services.
  3. *Tiễu trừ tận gốc (Eradication)*: Xóa file rác trong `%TEMP%`, chặn mã băm SHA-256 trên Firewall/EDR.
  4. *Gia cố hệ thống (Hardening)*: Hướng dẫn quét Full Scan với Windows Defender, bật bảo vệ thư mục chống Ransomware.
- **Tự động sinh Script PowerShell (`.ps1`)**:
  - Kiểm tra quyền Administrator trước khi chạy.
  - Tự động diệt tiến trình đang chạy trùng tên tệp.
  - Tạo thư mục cách ly an toàn `C:\Malware_Quarantine` và đổi tên tệp với phần mở rộng `.quarantine`.
  - Quét và xóa các khóa Registry tự khởi động liên quan đến tệp độc.

---

### 3.6. Giao Diện Web Dashboard (`app.py` & Frontend)
Xây dựng giao diện Dark Mode phong cách Trung tâm điều hành an ninh mạng (SOC / Cyber Security):
- Hỗ trợ kéo thả file thực thi (`.exe`, `.dll`) để quét trực tiếp.
- Khung nhập VirusTotal API Key linh hoạt.
- 3 nút **Quét Demo Mẫu** chuẩn bị sẵn cho buổi bảo vệ đồ án.
- Biểu đồ đồng hồ đo chỉ số rủi ro (Risk Gauge 0 - 100%).
- Thanh trực quan hóa Shannon Entropy từng Section với mã màu cảnh báo.
- Bảng chi tiết bóc tách hàm băm, các API nhạy cảm và thẻ lý do AI (XAI).
- Hộp thoại xem trước quy trình khắc phục và nút **Tải Script PowerShell (.ps1)**.

---

## 4. Cấu Trúc Thư Mục Dự Án

```
DA_BMTT/
├── .venv/                      # Môi trường ảo Python (Đã cài sẵn thư viện)
├── static/                     # Tài nguyên giao diện người dùng
│   ├── css/
│   │   └── style.css           # Giao diện Cyber Security Dark Mode hiện đại
│   └── js/
│       └── app.js              # Xử lý kéo thả, gọi REST API, vẽ biểu đồ
├── templates/
│   └── index.html              # Trang chủ Web Dashboard trực quan
├── ai_engine.py                # Mô-đun AI Random Forest + XAI Heuristics
├── app.py                      # Máy chủ Flask Backend & RESTful API
├── cloud_threat_intel.py       # Mô-đun tra cứu đám mây VirusTotal API v3 & Cache
├── hybrid_detector.py          # Động cơ phán quyết lai kết hợp Static + AI + Cloud
├── remediation_engine.py       # Mô-đun ứng phó sự cố & sinh script PowerShell
├── static_analyzer.py          # Bóc tách cấu trúc PE, Entropy, Packer, nhạy cảm API
├── malware_rf_model.pkl        # Tệp mô hình Machine Learning đã huấn luyện sẵn
├── vt_cache.json               # Bộ nhớ đệm cache kết quả VirusTotal
├── sample.exe                  # Mẫu tệp thực thi dùng để kiểm thử
├── requirements.txt            # Danh sách các thư viện Python phụ thuộc
├── run_app.bat                 # File tiện ích 1-Click khởi chạy ứng dụng
└── README.md                   # Tài liệu hướng dẫn & thuyết minh đồ án
```

---

## 5. Hướng Dẫn Triển Khai & Khởi Chạy

### Cách 1: Khởi chạy 1-Click bằng `run_app.bat` (Khuyên dùng)
1. Mở thư mục dự án `c:\laragon\laragon\www\DA_BMTT`.
2. Nhấp đúp chuột vào file:  
   👉 **`run_app.bat`**
3. Cửa sổ dòng lệnh sẽ tự động khởi động máy chủ Flask và tự mở trình duyệt web tại địa chỉ:  
   🌐 **`http://127.0.0.1:5000`**

---

### Cách 2: Khởi chạy Web Server bằng PowerShell / CMD
1. Mở PowerShell tại thư mục dự án:
   ```powershell
   cd c:\laragon\laragon\www\DA_BMTT
   ```
2. Chạy ứng dụng bằng Python trong môi trường ảo `.venv`:
   ```powershell
   .\.venv\Scripts\python.exe app.py
   ```
3. Mở trình duyệt web bất kỳ (Chrome, Edge, Firefox) và truy cập:  
   👉 **`http://127.0.0.1:5000`**

---

### Cách 3: Chạy Quét Nhanh Bằng Dòng Lệnh (CLI)
Nếu muốn kiểm tra một tệp nhanh mà không cần mở giao diện Web:
```powershell
.\.venv\Scripts\python.exe hybrid_detector.py <đường_dẫn_file>
```

**Ví dụ:**
```powershell
.\.venv\Scripts\python.exe hybrid_detector.py sample.exe
```
Kết quả trả về sẽ là chuỗi JSON đầy đủ chứa: mã băm, chỉ số entropy, phân tích PE sections, cảnh báo API, điểm tin cậy AI, danh tiếng đám mây và toàn bộ nội dung kịch bản PowerShell khắc phục.

---

## 6. Kịch Bản Thuyết Minh & Trình Diễn Đồ Án (Demo Walkthrough)

Để gây ấn tượng tốt nhất trong buổi báo cáo hoặc bảo vệ đồ án với hội đồng chấm thi, bạn có thể thực hiện theo 4 kịch bản có sẵn trên giao diện:

### Kịch bản 1: Minh họa Tra cứu Mối đe dọa Đám mây (Mẫu WannaCry)
- **Thao tác**: Nhấp vào nút **"WannaCry Ransomware"** trên giao diện Web.
- **Ý nghĩa thuyết minh**:
  - Tệp có mã băm SHA-256 trùng khớp với mẫu mã độc tống tiền nổi tiếng WannaCry.
  - Đám mây VirusTotal phát hiện $68/72$ hãng bảo mật cảnh báo (Microsoft, Kaspersky, CrowdStrike...).
  - Hệ thống kết luận **`MALICIOUS`** với điểm rủi ro $98.5\%$.
  - Tab *Biện pháp khắc phục* tự động nhận diện mối đe dọa là **Ransomware** và khuyến nghị ngắt mạng LAN khẩn cấp để chống lây lan.

### Kịch bản 2: Minh họa Khả năng Bắt Mã độc Mới / Zero-Day bằng AI Tại Chỗ
- **Thao tác**: Nhấp vào nút **"Zero-Day Obfuscated"** trên giao diện Web.
- **Ý nghĩa thuyết minh**:
  - Tệp hoàn toàn mới, chưa từng được ai tải lên VirusTotal (Cloud trả về `404 Not Found`).
  - Nếu chỉ dùng phương pháp tra cứu đám mây truyền thống thì sẽ kết luận sai là file an toàn.
  - Tuy nhiên, **Phân tích tĩnh tại chỗ** phát hiện: Section đóng gói `.UPX`, độ hỗn loạn entropy rất cao ($7.84/8.0$), gọi các API nguy hiểm (`VirtualAlloc`, `WriteProcessMemory`).
  - **Mô hình AI tại chỗ** nhận diện bất thường và kết luận: **`SUSPICIOUS_UNKNOWN`** (File lạ / Nghi vấn mã độc Zero-Day), chứng minh tính ưu việt của phương pháp lai.

### Kịch bản 3: Minh họa Kiểm tra File Sạch Tiêu Chuẩn (Benign Utility)
- **Thao tác**: Nhấp vào nút **"Clean Utility"** trên giao diện Web.
- **Ý nghĩa thuyết minh**:
  - Tệp sạch thông thường có entropy vừa phải ($5.82$), không có section nén packer, không gọi API tiêm nhiễm.
  - Cả Đám mây và AI cục bộ đều đồng thuận xác nhận file an toàn: **`BENIGN`** (Rủi ro $5.0\%$).

### Kịch bản 4: Quét Tệp Thực Tế & Tải Kịch Bản PowerShell
- **Thao tác**: Kéo thả bất kỳ file `.exe` thật hoặc tệp `sample.exe` có sẵn trong thư mục vào ô tải lên.
- Xem chi tiết bảng phân tích các Section và API nhạy cảm.
- Chuyển sang tab **"Biện pháp khắc phục"** và bấm nút **"Tải Script Remediation (.ps1)"** để tải về kịch bản xử lý tự động.

---

## 7. Các Thư Viện Sử Dụng & Yêu Cầu Môi Trường

Hệ thống hoạt động tương thích hoàn toàn trên hệ điều hành **Windows 10 / 11** với Python 3.10 trở lên. Các gói thư viện chính trong `requirements.txt`:

| Thư viện | Phiên bản | Vai trò trong hệ thống |
| :--- | :---: | :--- |
| **`Flask`** | `>= 2.2` | Máy chủ Web Backend cung cấp RESTful API và giao diện Dashboard. |
| **`pefile`** | `>= 2023.2` | Thư viện chuyên dụng bóc tách cấu trúc PE Header, Section, Import Table. |
| **`scikit-learn`** | `>= 1.2` | Xây dựng và thực thi mô hình Machine Learning `RandomForestClassifier`. |
| **`joblib`** | `>= 1.2` | Đọc và lưu trữ mô hình học máy nhị phân (`.pkl`). |
| **`requests`** | `>= 2.28` | Gửi HTTP Request truy vấn VirusTotal Cloud API v3. |
| **`numpy`** | `>= 1.23` | Xử lý ma trận dữ liệu vector đặc trưng và tính toán phân phối xác suất. |

---

*© Đồ án Bảo Mật Thông Tin (DA_BMTT) - Hệ Thống Phát Hiện Mã Độc Lai Kết Hợp Phân Tích Tĩnh & Tri Thức Đám Mây.*
