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

        # 4. Cơ chế ra quyết định lai (Hybrid Decision Logic)
        final_verdict = "BENIGN"
        risk_score = 0.0
        decision_rule = ""
        explanation = ""

        cloud_status = cloud_res.get("status")
        cloud_positives = cloud_res.get("positives", 0)
        cloud_score = cloud_res.get("cloud_score", 0.0)
        ai_conf = ai_res.get("ai_confidence", 0.0)
        ai_label = ai_res.get("ai_label", "BENIGN")

        # Trường hợp 1: Đồng thuận đám mây mạnh (Cloud Consensus)
        if cloud_status == "FOUND" and cloud_positives >= 5:
            final_verdict = "MALICIOUS"
            risk_score = max(cloud_score, ai_conf, 0.85)
            decision_rule = "Cloud Threat Consensus (Đám mây xác thực cao)"
            explanation = f"Phát hiện bởi {cloud_positives}/{cloud_res.get('total')} hãng bảo mật trên mạng lưới toàn cầu. Chủng loại: {cloud_res.get('threat_classification')}."

        # Trường hợp 2: Đám mây nghi vấn nhẹ (1 đến 4 hãng cảnh báo)
        elif cloud_status == "FOUND" and cloud_positives >= 1:
            risk_score = round(0.5 * cloud_score + 0.5 * ai_conf, 4)
            if ai_label == "MALICIOUS" or risk_score >= 0.50:
                final_verdict = "MALICIOUS"
                decision_rule = "Cloud-AI Corroborated Verdict"
                explanation = "Có cảnh báo từ đám mây kết hợp mô hình AI phát hiện các đặc trưng nguy hiểm trong mã nhị phân."
            else:
                final_verdict = "SUSPICIOUS_UNKNOWN"
                decision_rule = "Low Cloud Detections / Anomaly"
                explanation = f"Có {cloud_positives} hãng AV cảnh báo nhưng AI đánh giá rủi ro vừa phải. Đưa vào diện tệp lạ cần giám sát."

        # Trường hợp 3: Tệp mới (Zero-Day) hoặc Chế độ Offline / Không có API Key
        elif cloud_status in ["NOT_FOUND", "NO_API_KEY", "RATE_LIMITED", "NETWORK_ERROR"]:
            risk_score = ai_conf
            if ai_label == "MALICIOUS":
                final_verdict = "MALICIOUS"
                decision_rule = "Local AI Zero-Day Detection (Mô hình phát hiện mã độc mới)"
                explanation = "Tệp chưa từng có chữ ký trên đám mây nhưng AI phát hiện các chuỗi đặc trưng tương đồng cao với họ mã độc đã biết."
            elif ai_label == "SUSPICIOUS_UNKNOWN":
                final_verdict = "SUSPICIOUS_UNKNOWN"
                decision_rule = "Local AI Anomaly Detection (Tệp lạ có cấu trúc bất thường)"
                explanation = "Tệp chưa xuất hiện trên đám mây và sở hữu các đặc trưng bất thường (Entropy cao, hàm API nhạy cảm hoặc cấu trúc nén packer)."
            else:
                final_verdict = "BENIGN"
                decision_rule = "Local AI Benign Verification (Xác minh an toàn tại chỗ)"
                explanation = "Tệp có cấu trúc tiêu chuẩn, không phát hiện dấu hiệu packer hay hành vi can thiệp hệ thống nguy hiểm."

        # Trường hợp 4: Kết hợp trọng số tiêu chuẩn
        else:
            risk_score = round(0.6 * cloud_score + 0.4 * ai_conf, 4)
            if risk_score >= 0.65:
                final_verdict = "MALICIOUS"
            elif risk_score >= 0.35:
                final_verdict = "SUSPICIOUS_UNKNOWN"
            else:
                final_verdict = "BENIGN"
            decision_rule = "Weighted Hybrid Decision"
            explanation = "Đánh giá dựa trên trọng số cân bằng giữa phân tích tĩnh AI và danh tiếng đám mây."

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