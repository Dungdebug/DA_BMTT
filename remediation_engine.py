import os
from datetime import datetime

class RemediationEngine:
    @classmethod
    def generate_playbook(cls, target_file, metadata, ai_analysis, cloud_analysis, final_verdict, risk_score):
        """
        Phân tích rủi ro đa chiều và đưa ra kịch bản ứng phó sự cố (Incident Response Playbook),
        giải pháp khắc phục chi tiết và mã kịch bản tự động hóa (PowerShell).
        """
        filename = metadata.get("filename", os.path.basename(target_file))
        sha256 = metadata.get("sha256", "")
        suspicious_apis = metadata.get("suspicious_apis", {})
        threat_class = cloud_analysis.get("threat_classification", "")
        ai_reasons = ai_analysis.get("xai_reasons", [])

        # 1. Xác định mức độ nghiêm trọng (Severity)
        if final_verdict == "MALICIOUS":
            if "ransom" in threat_class.lower() or risk_score >= 0.85:
                severity = "CRITICAL"
                severity_color = "#e53e3e"
            else:
                severity = "HIGH"
                severity_color = "#dd6b20"
        elif final_verdict == "SUSPICIOUS_UNKNOWN":
            severity = "MEDIUM"
            severity_color = "#d69e2e"
        else:
            severity = "INFO"
            severity_color = "#38a169"

        # 2. Nhận diện chủng loại nguy cơ
        detected_categories = []
        if "ransom" in threat_class.lower():
            detected_categories.append("Ransomware (Mã độc tống tiền / Mã hóa dữ liệu)")
        if "trojan" in threat_class.lower():
            detected_categories.append("Trojan (Mã độc giả mạo chiếm quyền điều khiển)")
        if len(suspicious_apis.get("injection", [])) > 0:
            detected_categories.append("Process Injection (Tiêm mã độc vào bộ nhớ tiến trình hệ thống)")
        if len(suspicious_apis.get("persistence", [])) > 0:
            detected_categories.append("Persistence Mechanism (Tự gắn vào Registry / Service để khởi động cùng Windows)")
        if len(suspicious_apis.get("network", [])) > 0:
            detected_categories.append("Network C2 / Dropper (Kết nối máy chủ điều khiển và tải tệp từ xa)")
        if len(suspicious_apis.get("spying", [])) > 0:
            detected_categories.append("Spyware / Keylogger (Đánh cắp bàn phím và dữ liệu nhạy cảm)")
        if metadata.get("has_suspicious_section") or metadata.get("overall_entropy", 0) > 7.2:
            detected_categories.append("Packer / Obfuscated Crypter (Mã hóa nén lớp vỏ để lẩn tránh Antivirus)")

        if not detected_categories:
            if final_verdict == "MALICIOUS":
                detected_categories.append("Generic Malware (Mã độc tổng hợp)")
            elif final_verdict == "SUSPICIOUS_UNKNOWN":
                detected_categories.append("Suspicious / Zero-Day Binary (Tệp lạ có cấu trúc bất thường)")
            else:
                detected_categories.append("Benign Software (Tệp phần mềm thông thường, chưa phát hiện hành vi độc)")

        # 3. Xây dựng các bước hành động cụ thể
        immediate_actions = []
        investigation_steps = []
        eradication_steps = []
        hardening_steps = []

        if final_verdict in ["MALICIOUS", "SUSPICIOUS_UNKNOWN"]:
            # Bước tức thì
            immediate_actions.append({
                "action": "Cách ly tệp (Quarantine)",
                "detail": f"Di chuyển ngay tệp '{filename}' vào thư mục cách ly an toàn (ví dụ: 'C:\\Quarantine\\') và đổi đuôi tệp thành '.locked' để vô hiệu hóa khả năng kích hoạt ngẫu nhiên."
            })
            immediate_actions.append({
                "action": "Chấm dứt tiến trình liên quan (Terminate Process)",
                "detail": f"Kiểm tra Task Manager và hủy ngay mọi tiến trình đang chạy từ tệp '{filename}' bằng lệnh Taskkill hoặc PowerShell."
            })
            if "network" in str(detected_categories).lower() or "ransom" in str(detected_categories).lower():
                immediate_actions.append({
                    "action": "Ngắt kết nối mạng khẩn cấp",
                    "detail": "Tạm thời ngắt kết nối mạng LAN/Wi-Fi của máy để ngăn mã độc liên lạc máy chủ C2 tải payload phụ hoặc lây lan sang các máy trạm khác trong mạng nội bộ."
                })

            # Bước điều tra
            investigation_steps.append({
                "target": "Kiểm tra Registry Persistence",
                "detail": "Rà soát các nhánh Run/RunOnce tại:\n• HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n• HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            })
            investigation_steps.append({
                "target": "Kiểm tra Thư mục Khởi động (Startup)",
                "detail": "Kiểm tra thư mục: '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup' xem có shortcut trỏ tới tệp lạ hay không."
            })
            investigation_steps.append({
                "target": "Kiểm tra Scheduled Tasks & Services",
                "detail": "Mở Task Scheduler (taskschd.msc) và Windows Services (services.msc) để tìm các tác vụ mới tạo trong thời gian gần đây."
            })

            # Bước tiễu trừ
            eradication_steps.append({
                "step": "Xóa triệt để tệp và các tệp đệm",
                "detail": f"Sau khi đã lấy mẫu điều tra, xóa vĩnh viễn tệp '{filename}' và dọn dẹp thư mục tạm %TEMP% cùng %APPDATA%."
            })
            eradication_steps.append({
                "step": "Chặn mã băm (Hash Blacklist)",
                "detail": f"Thêm mã băm SHA-256 '{sha256}' vào danh sách đen (Blacklist) của hệ thống phòng thủ EDR / Firewall doanh nghiệp."
            })

            # Bước gia cố
            hardening_steps.append({
                "step": "Quét toàn bộ hệ thống bằng phần mềm chuyên dụng",
                "detail": "Thực hiện Full Scan bằng Windows Defender Offline hoặc các giải pháp EDR (Kaspersky, CrowdStrike, Malwarebytes)."
            })
            hardening_steps.append({
                "step": "Bảo vệ chống Ransomware",
                "detail": "Bật tính năng 'Controlled Folder Access' trong Windows Security để bảo vệ các thư mục tài liệu quan trọng."
            })
        else:
            immediate_actions.append({
                "action": "Không cần cách ly khẩn cấp",
                "detail": "Tệp được đánh giá an toàn, không mang các hành vi can thiệp hệ thống nguy hiểm."
            })
            investigation_steps.append({
                "target": "Xác minh nguồn gốc tải về",
                "detail": "Nếu tệp được tải từ nguồn không chính thống, nên kiểm tra chữ ký số (Digital Signature) của nhà phát hành."
            })
            eradication_steps.append({
                "step": "Giám sát thông thường",
                "detail": "Duy trì hoạt động giám sát thời gian thực của Windows Defender."
            })
            hardening_steps.append({
                "step": "Cập nhật định kỳ",
                "detail": "Luôn giữ hệ điều hành và cơ sở dữ liệu diệt virus ở phiên bản mới nhất."
            })

        # 4. Sinh mã kịch bản PowerShell tự động hóa (PowerShell Incident Response Script)
        powershell_script = cls._generate_powershell_script(target_file, filename, sha256, final_verdict)

        return {
            "severity": severity,
            "severity_color": severity_color,
            "detected_threat_categories": detected_categories,
            "immediate_actions": immediate_actions,
            "investigation_steps": investigation_steps,
            "eradication_steps": eradication_steps,
            "hardening_steps": hardening_steps,
            "powershell_script": powershell_script
        }

    @staticmethod
    def _generate_powershell_script(target_file, filename, sha256, verdict):
        """
        Tạo mã kịch bản PowerShell để quản trị viên có thể chạy tự động cách ly và rà soát hệ thống.
        """
        process_name = os.path.splitext(filename)[0]
        sanitized_path = target_file.replace("\\", "\\\\")

        script = f"""# ==============================================================================
# KỊCH BẢN XỬ LÝ SỰ CỐ AN TOÀN THÔNG TIN TỰ ĐỘNG (INCIDENT RESPONSE SCRIPT)
# Đề tài: Phát hiện mã độc lai (Static Analysis + Cloud Threat Intel + AI Heuristics)
# Tệp mục tiêu : {filename}
# SHA-256       : {sha256}
# Đánh giá      : {verdict}
# Thời gian tạo : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# ==============================================================================

# Yêu cầu quyền Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Write-Warning "Vui long chay PowerShell duoi quyen Administrator (Run as Administrator)!"
    Exit
}}

Write-Host ">>> DANG BAT DAU TIEN TRINH UNG PHO SU CO CHO: {filename}" -ForegroundColor Cyan

# 1. HỦY TIẾN TRÌNH ĐANG CHẠY LIÊN QUAN
Write-Host "[1/4] Kiem tra va dung tien trinh nghi van..." -ForegroundColor Yellow
$proc = Get-Process -Name "{process_name}" -ErrorAction SilentlyContinue
if ($proc) {{
    Stop-Process -Name "{process_name}" -Force -ErrorAction SilentlyContinue
    Write-Host "  -> Da buoc dung tien trinh {process_name} (PID: $($proc.Id))" -ForegroundColor Red
}} else {{
    Write-Host "  -> Khong co tien trinh nao mang ten {process_name} dang thuc thi." -ForegroundColor Green
}}

# 2. CÁCH LY TỆP VÀO VÙNG AN TOÀN (QUARANTINE)
Write-Host "[2/4] Cach ly tep tin vao thu muc an toan..." -ForegroundColor Yellow
$QuarantineDir = "C:\\Malware_Quarantine"
if (-not (Test-Path -Path $QuarantineDir)) {{
    New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
}}

$TargetFilePath = "{sanitized_path}"
if (Test-Path -Path $TargetFilePath) {{
    $QuarantineFile = Join-Path $QuarantineDir ("{filename}_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".quarantine")
    Move-Item -Path $TargetFilePath -Destination $QuarantineFile -Force
    Write-Host "  -> Tep da duoc cach ly tai: $QuarantineFile" -ForegroundColor Red
}} else {{
    Write-Host "  -> Tep khong ton tai o duong dan ban dau hoac da bi xoa." -ForegroundColor Gray
}}

# 3. RÀ SOÁT CÁC ĐIỂM DUY TRÌ KHỞI ĐỘNG (PERSISTENCE CHECK)
Write-Host "[3/4] Ra soat khoa Registry Run/RunOnce..." -ForegroundColor Yellow
$RegPaths = @(
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
)
foreach ($reg in $RegPaths) {{
    if (Test-Path $reg) {{
        $items = Get-ItemProperty -Path $reg
        foreach ($prop in $items.PSObject.Properties) {{
            if ($prop.Value -like "*{filename}*") {{
                Write-Host "  [CANH BAO] Phat hien Registry Entry nguy hiem: $($prop.Name) -> $($prop.Value)" -ForegroundColor Magenta
                # Xoa khoa nguy hiem
                Remove-ItemProperty -Path $reg -Name $prop.Name -Force
                Write-Host "  -> Da xoa khoa registry duy tri thanh cong." -ForegroundColor Green
            }}
        }}
    }}
}}

# 4. THÔNG BÁO HOÀN TẤT
Write-Host "[4/4] Hoan tat quy trinh cach ly va xu ly co ban." -ForegroundColor Green
Write-Host "Khuyen nghi: Hay khoi dong lai may va chay Full Scan voi Windows Defender hoac Antivirus chuyen dung!" -ForegroundColor Cyan
"""
        return script
