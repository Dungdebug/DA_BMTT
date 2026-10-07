import os
import sys
import json
from datetime import datetime
from static_analyzer import StaticAnalyzer
from ai_engine import AIEngine
from cloud_threat_intel import CloudThreatIntel
from remediation_engine import RemediationEngine

class HybridDetector:
    def __init__(self, vt_api_key=""):
        self.ai = AIEngine()
        self.cloud = CloudThreatIntel(api_key=vt_api_key)

    def scan(self, file_path):
        """
        Thực hiện toàn trình quét mã độc lai:
        1. Phân tích tĩnh cấu trúc file (Static Analysis)
        2. Suy luận bằng học máy cục bộ (Local AI Engine & XAI)
        3. Tra cứu tri thức mối đe dọa đám mây (Cloud Threat Intel)
        4. Tổng hợp phán quyết lai (Hybrid Decision Engine)
        5. Đề xuất quy trình ứng phó & kịch bản khắc phục (Remediation Playbook)
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Tệp không tồn tại: {file_path}")

        # 1. Trích xuất đặc trưng tĩnh
        features, metadata = StaticAnalyzer.extract_features(file_path)
        
        # 2. Suy luận bằng AI tại chỗ
        ai_res = self.ai.predict(features)

        # 3. Tra cứu Threat Intelligence đám mây (VirusTotal)
        cloud_res = self.cloud.lookup_hash(metadata["sha256"])

        # 4. Cơ chế ra quyết định lai (Hybrid Decision Logic - Weighted Scoring)
        final_verdict = "BENIGN"
        decision_rule = ""
        explanation = ""

        cloud_status = cloud_res.get("status")
        cloud_score = cloud_res.get("cloud_score", 0.0)
        ai_conf = ai_res.get("ai_confidence", 0.0)
        
        # Tính điểm S_static (dựa trên các dấu hiệu nghi ngờ tĩnh)
        s_static = 0.0
        if metadata.get("max_section_entropy", 0) > 7.0:
            s_static += 0.3
        if metadata.get("has_suspicious_section", False):
            s_static += 0.3
        if metadata.get("size_anomaly_count", 0) > 0:
            s_static += 0.2
        if metadata.get("suspicious_api_count", 0) > 3:
            s_static += 0.2
            
        s_static = min(1.0, s_static) # Giới hạn tối đa là 1.0
        
        # Tra cứu nhanh Imphash trên CTI (Mô phỏng nâng điểm nếu Imphash giống mã độc biết trước)
        imphash = metadata.get("imphash", "")
        # Ví dụ một số imphash nổi tiếng của Ransomware/Trojan
        ransomware_imphashes = [
            "f43c3f96614457e5e7ab3d27464ef245", # WannaCry
            "b34f154ec913d2d2c435cbd644e91687", # Locky
            "178ce5ce12d3e5e40e69db9e64d7c041", # Emotet
            "8f3226dbdbf970eabac5ac88a5ea1134"  # Trickbot
        ]
        if imphash in ransomware_imphashes:
            cloud_score = max(cloud_score, 0.90) # Tự động nâng điểm CTI nếu trúng imphash độc hại
            explanation += f"[!] Cảnh báo CTI: Imphash '{imphash}' trùng khớp với mã độc (Ransomware/Trojan) đã biết. "

        # CƠ CHẾ TRỌNG SỐ ĐỘNG (Dynamic Weighting)
        # Nếu file đã có trên Cloud hoặc Cloud phát hiện Imphash
        if cloud_status == "FOUND" or cloud_score > 0:
            # Risk Score = 0.25 * S_static + 0.35 * P_ml + 0.40 * S_cti
            risk_score = round((0.25 * s_static) + (0.35 * ai_conf) + (0.40 * cloud_score), 4)
            decision_rule = "Weighted Hybrid Decision (Có CTI)"
        else:
            # File Zero-day / Không có mạng / Không có Cloud -> Phân bổ lại 40% trọng số của CTI
            # Static: 0.25 -> 0.40, ML: 0.35 -> 0.60
            risk_score = round((0.40 * s_static) + (0.60 * ai_conf), 4)
            decision_rule = "Local Zero-Day Decision (Không có CTI)"

        # Phân loại dựa trên ngưỡng
        if risk_score >= 0.70:
            final_verdict = "MALICIOUS"
            decision_rule += " | Score >= 0.70 (Cách ly)"
            explanation += "Hệ thống xác định tệp có mức độ rủi ro cao dựa trên tổng hợp phân tích đa tầng."
        elif risk_score >= 0.40:
            final_verdict = "SUSPICIOUS_UNKNOWN"
            decision_rule += " | 0.40 <= Score < 0.70 (Gợi ý Sandbox)"
            explanation += "Tệp nằm trong vùng nghi ngờ (Suspicious), có chứa các đặc trưng bất thường cần giám sát."
        else:
            final_verdict = "BENIGN"
            decision_rule += " | Score < 0.40 (An toàn)"
            explanation += "Tệp lành tính, cấu trúc và hành vi được dự đoán an toàn."

        # 5. Sinh quy trình ứng phó & kịch bản khắc phục
        remediation = RemediationEngine.generate_playbook(
            target_file=file_path,
            metadata=metadata,
            ai_analysis=ai_res,
            cloud_analysis=cloud_res,
            final_verdict=final_verdict,
            risk_score=risk_score
        )

        return {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_info": {
                "file_path": file_path,
                "filename": metadata["filename"],
                "file_size": metadata["file_size"],
                "is_pe": metadata["is_pe"],
                "md5": metadata["md5"],
                "sha1": metadata["sha1"],
                "sha256": metadata["sha256"],
                "imphash": metadata["imphash"]
            },
            "static_analysis": {
                "overall_entropy": metadata["overall_entropy"],
                "max_section_entropy": metadata["max_section_entropy"],
                "num_sections": metadata["num_sections"],
                "num_imported_dlls": metadata["num_imported_dlls"],
                "num_imported_funcs": metadata["num_imported_funcs"],
                "has_suspicious_section": metadata["has_suspicious_section"],
                "size_anomaly_count": metadata["size_anomaly_count"],
                "sections": metadata["sections"],
                "suspicious_apis": metadata["suspicious_apis"]
            },
            "ai_analysis": ai_res,
            "cloud_analysis": cloud_res,
            "hybrid_decision": {
                "final_verdict": final_verdict,
                "overall_risk_score": round(float(risk_score), 4),
                "risk_percentage": f"{round(float(risk_score) * 100, 1)}%",
                "applied_rule": decision_rule,
                "verdict_explanation": explanation
            },
            "remediation": remediation
        }

if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    API_KEY = ""
    detector = HybridDetector(vt_api_key=API_KEY)

    target = sys.argv[1] if len(sys.argv) > 1 else "sample.exe"
    
    # Tạo thử 1 file test nếu chưa có
    if not os.path.exists(target):
        with open(target, "wb") as f:
            f.write(b"MZ" + b"\x90" * 1024)

    report = detector.scan(target)
    print(json.dumps(report, indent=2, ensure_ascii=False))