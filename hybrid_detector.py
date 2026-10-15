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

        # GUARDRAIL 0: TỆP RỖNG HOẶC KHÔNG CHỨA DỮ LIỆU THỰC THI (EMPTY FILE GUARDRAIL)
        if metadata.get("file_size", 0) == 0:
            final_verdict = "BENIGN"
            risk_score = 0.0
            remediation = RemediationEngine.generate_playbook(
                target_file=metadata["filename"],
                metadata=metadata,
                ai_analysis=ai_res,
                cloud_analysis=cloud_res,
                final_verdict=final_verdict,
                risk_score=risk_score
            )
            return {
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "file_info": metadata,
                "static_analysis": metadata,
                "ai_analysis": ai_res,
                "cloud_analysis": cloud_res,
                "hybrid_decision": {
                    "final_verdict": final_verdict,
                    "overall_risk_score": 0.0,
                    "risk_percentage": "0.0%",
                    "applied_rule": "Empty File Guardrail (Tệp rỗng)",
                    "verdict_explanation": "Tệp có dung lượng 0 bytes, hoàn toàn rỗng và không chứa bất kỳ mã thực thi nào."
                },
                "remediation": remediation
            }

        # 4. Cơ chế ra quyết định lai tương hỗ (3-Tier Synergistic Decision Engine)
        final_verdict = "BENIGN"
        decision_rule = ""
        explanation = ""
        synergy_mode = ""

        cloud_status = cloud_res.get("status")
        cloud_score = cloud_res.get("cloud_score", 0.0)
        ai_conf = ai_res.get("ai_confidence", 0.0)
        
        # A. Tính điểm nghi ngờ từ Phân tích tĩnh (S_static)
        s_static = 0.0
        static_flags = []
        if metadata.get("max_section_entropy", 0) > 7.0:
            s_static += 0.30
            static_flags.append(f"Entropy cao ({metadata.get('max_section_entropy', 0):.2f}/8.0)")
        if metadata.get("has_suspicious_section", False):
            s_static += 0.30
            static_flags.append("Section nén/giấu mã (Packer)")
        if metadata.get("size_anomaly_count", 0) > 0:
            s_static += 0.20
            static_flags.append("Bất thường VirtualSize >> RawData")
        if metadata.get("suspicious_api_count", 0) > 3:
            s_static += 0.20
            static_flags.append(f"Chứa {metadata.get('suspicious_api_count', 0)} Windows API nhạy cảm")
            
        s_static = min(1.0, s_static)
        
        # B. Tra cứu nhanh Imphash trên CTI (Bổ trợ chéo giữa Phân tích tĩnh và Tri thức đám mây)
        imphash = metadata.get("imphash", "")
        ransomware_imphashes = {
            "f43c3f96614457e5e7ab3d27464ef245": "WannaCry Ransomware",
            "b34f154ec913d2d2c435cbd644e91687": "Locky Ransomware",
            "178ce5ce12d3e5e40e69db9e64d7c041": "Emotet Banking Trojan",
            "8f3226dbdbf970eabac5ac88a5ea1134": "Trickbot Trojan"
        }
        if imphash in ransomware_imphashes:
            cloud_score = max(cloud_score, 0.95)
            explanation += f"[!] Bổ trợ CTI: Imphash '{imphash}' trùng khớp hoàn toàn với dòng {ransomware_imphashes[imphash]}. "

        # C. CƠ CHẾ PHỐI HỢP BỔ TRỢ TƯƠNG HỖ 3 TẦNG:
        if cloud_status == "FOUND" and cloud_score >= 0.70:
            # Kịch bản 1: MỐI ĐE DỌA ĐÃ BIẾT (Known Threat Consensus)
            synergy_mode = "KNOWN_THREAT_CORROBORATION"
            risk_score = round((0.20 * s_static) + (0.30 * ai_conf) + (0.50 * cloud_score), 4)
            decision_rule = "Đồng thuận Mối đe dọa đã biết (CTI Lead + AI/Static Explain)"
            final_verdict = "MALICIOUS"
            explanation += "Tri thức đám mây CTI đã ghi nhận tệp này là mã độc. Động cơ AI và phân tích tĩnh đã bóc tách cơ chế tiêm nhiễm và cấu trúc chi tiết."

        elif cloud_status != "FOUND" or cloud_score == 0.0:
            # Kịch bản 2: PHÒNG THỦ ZERO-DAY / FILE MỚI (Zero-Day Synergistic Defense)
            synergy_mode = "ZERO_DAY_DEFENSE"

            # GUARDRAIL: Nếu phân tích tĩnh hoàn toàn sạch (0 cảnh báo, 0 API độc hại, entropy bình thường)
            is_clean_software = (
                s_static == 0.0 and 
                metadata.get("suspicious_api_count", 0) == 0 and 
                not metadata.get("has_suspicious_section", False) and
                metadata.get("size_anomaly_count", 0) == 0 and
                metadata.get("overall_entropy", 0) <= 6.6
            )

            if is_clean_software:
                risk_score = 0.02
                final_verdict = "BENIGN"
                decision_rule = "Clean Software Guardrail (Phần mềm sạch đã kiểm định)"
                explanation = "Tệp C++ hoặc phần mềm sạch đã vượt qua kiểm tra cấu trúc nghiêm ngặt. Không phát hiện bất kỳ API tiêm nhiễm, duy trì, né tránh hay kết nối C2 nào."
            else:
                # Phân bổ lại trọng số: AI (65%) + Static (35%)
                risk_score = round((0.35 * s_static) + (0.65 * ai_conf), 4)
                decision_rule = "Bổ trợ Phòng thủ Zero-Day (AI & Static tại chỗ)"
                
                if risk_score >= 0.70:
                    final_verdict = "MALICIOUS"
                    explanation += "Cảnh báo Zero-Day: Tệp chưa từng xuất hiện trên đám mây CTI nhưng AI phát hiện mẫu hành vi độc hại cao cùng các bất thường cấu trúc tĩnh."
                elif risk_score >= 0.40:
                    final_verdict = "SUSPICIOUS_UNKNOWN"
                    explanation += "Tệp mới chưa có trên CTI, mang đặc trưng cấu trúc đáng ngờ. Khuyến nghị gửi lên môi trường Sandbox để phân tích động."
                else:
                    final_verdict = "BENIGN"
                    explanation += "Tệp mới chưa có trên CTI nhưng AI và phân tích tĩnh đánh giá cấu trúc an toàn, lành tính."

        else:
            # Kịch bản 3: PHÁN QUYẾT LAI CÂN BẰNG (Balanced Hybrid Scoring)
            synergy_mode = "BALANCED_HYBRID"
            risk_score = round((0.25 * s_static) + (0.35 * ai_conf) + (0.40 * cloud_score), 4)
            decision_rule = "Phán quyết Lai Cân Bằng (Static: 25%, AI: 35%, CTI: 40%)"
            
            if risk_score >= 0.70:
                final_verdict = "MALICIOUS"
                explanation += "Tổng hợp đa tầng xác định mức độ rủi ro nghiêm trọng."
            elif risk_score >= 0.40:
                final_verdict = "SUSPICIOUS_UNKNOWN"
                explanation += "Tệp có một số dấu hiệu bất thường từ CTI hoặc AI, cần cách ly theo dõi."
            else:
                final_verdict = "BENIGN"
                explanation += "Tệp lành tính, tổng điểm rủi ro nằm dưới ngưỡng an toàn."

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
                "synergy_mode": synergy_mode,
                "applied_rule": decision_rule,
                "static_flags": static_flags,
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