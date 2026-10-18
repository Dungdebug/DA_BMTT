import os
import sys
import json
import shutil
import tempfile
from flask import Flask, render_template, request, jsonify, Response, send_file
from hybrid_detector import HybridDetector
from cloud_threat_intel import CloudThreatIntel

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # Cho phép tải file tối đa 64MB

# Thư mục tạm để lưu file upload quét
UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), "malware_detector_uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Danh sách mẫu Demo sẵn sàng để thuyết minh đồ án
DEMO_SAMPLES = {
    "wannacry": {
        "id": "wannacry",
        "name": "WannaCry Ransomware (Demo Cloud Threat Intel)",
        "desc": "Mã độc tống tiền mã hóa dữ liệu với 68/72 hãng cảnh báo trên VirusTotal.",
        "type": "malicious_cloud",
        "simulated_hash": "ed01ebf83334a1f6f164887864750e527ec40e18c641f553e524d1e2ee60ea53"
    },
    "zeroday_packed": {
        "id": "zeroday_packed",
        "name": "Zero-Day Obfuscated Dropper (Demo AI Heuristics)",
        "desc": "File chưa có chữ ký trên đám mây (404), bị nén UPX, entropy 7.82, gọi VirtualAlloc & WriteProcessMemory.",
        "type": "zeroday_ai"
    },
    "benign_calc": {
        "id": "benign_calc",
        "name": "Windows System Utility (Demo File Sạch An Toàn)",
        "desc": "Tệp sạch tiêu chuẩn với cấu trúc PE hoàn chỉnh, entropy 5.6, không gọi API tiêm nhiễm.",
        "type": "benign"
    }
}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/demo-samples", methods=["GET"])
def get_demo_samples():
    return jsonify(list(DEMO_SAMPLES.values()))

@app.route("/api/scan", methods=["POST"])
def scan_file():
    vt_key = request.form.get("vt_api_key", "").strip()
    detector = HybridDetector(vt_api_key=vt_key)

    if "file" not in request.files:
        return jsonify({"error": "Vui lòng chọn một tệp để quét."}), 400

    uploaded_file = request.files["file"]
    if uploaded_file.filename == "":
        return jsonify({"error": "Tên tệp không hợp lệ."}), 400

    safe_filename = uploaded_file.filename.replace(" ", "_")
    saved_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    uploaded_file.save(saved_path)

    try:
        report = detector.scan(saved_path)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": f"Lỗi trong quá trình quét: {str(e)}"}), 500
    finally:
        # Giữ lại file một khoảng thời gian hoặc dọn dẹp nếu cần
        pass

@app.route("/api/demo-scan/<sample_id>", methods=["POST"])
def scan_demo_sample(sample_id):
    """
    Sinh file mẫu demo phù hợp để quét minh họa trong các buổi báo cáo/thuyết minh.
    """
    if sample_id not in DEMO_SAMPLES:
        return jsonify({"error": "Mẫu demo không tồn tại."}), 404

    vt_key = request.json.get("vt_api_key", "") if request.is_json else ""
    detector = HybridDetector(vt_api_key=vt_key)
    demo_info = DEMO_SAMPLES[sample_id]

    target_path = os.path.join(UPLOAD_FOLDER, f"demo_{sample_id}.exe")

    # Tạo nội dung nhị phân mô phỏng tương ứng
    if sample_id == "wannacry":
        # Tạo file nhị phân có hash cố định của WannaCry
        report = _generate_mock_wannacry_report(detector, demo_info)
        return jsonify(report)

    elif sample_id == "zeroday_packed":
        report = _generate_mock_zeroday_report(detector, demo_info)
        return jsonify(report)

    else:
        # File sạch tiêu chuẩn
        report = _generate_mock_benign_report(detector, demo_info)
        return jsonify(report)

def _generate_mock_wannacry_report(detector, demo_info):
    import numpy as np
    sha256 = demo_info["simulated_hash"]
    cloud_res = detector.cloud.lookup_hash(sha256)
    
    # Tạo vector 20 đặc trưng mô phỏng ransomware
    feat_vector = np.array([
        3514368, 4, 7.55, 7.82, 4, 18, 0, 1, 3, 2, 2, 2,
        258, 0, 2, 150000, 3200000, 4096, 45056, 0
    ], dtype=np.float32)
    ai_res = detector.ai.predict(feat_vector)

    metadata = {
        "filename": "WannaCryptor_Payload.exe",
        "file_size": 3514368,
        "is_pe": True,
        "md5": "84c82835a5d21bbcf75a61706d8ab549",
        "sha1": "5ff465acf83e72e392e697d82f31dc02ec2d018d",
        "sha256": sha256,
        "imphash": "b345373c12470129",
        "overall_entropy": 7.55,
        "max_section_entropy": 7.82,
        "num_sections": 4,
        "num_imported_dlls": 4,
        "num_imported_funcs": 18,
        "has_suspicious_section": False,
        "size_anomaly_count": 1,
        "sections": [
            {"name": ".text", "virtual_size": 150000, "raw_size": 145000, "entropy": 7.82, "is_suspicious": True},
            {"name": ".rdata", "virtual_size": 42000, "raw_size": 40960, "entropy": 6.95, "is_suspicious": False},
            {"name": ".data", "virtual_size": 80000, "raw_size": 20480, "entropy": 7.42, "is_suspicious": True},
            {"name": ".rsrc", "virtual_size": 3200000, "raw_size": 3200000, "entropy": 7.62, "is_suspicious": True}
        ],
        "suspicious_apis": {
            "injection": ["virtualalloc", "writeprocessmemory", "createremotethread"],
            "persistence": ["regsetvalueexa", "createservicea"],
            "evasion": ["isdebuggerpresent", "sleep"],
            "network": ["urldownloadtofilea", "internetopena"],
            "execution": ["winexec", "createprocessa"],
            "spying": []
        }
    }

    final_verdict = "MALICIOUS"
    risk_score = 0.985
    remediation = detector_remediation_gen(metadata, ai_res, cloud_res, final_verdict, risk_score)

    return {
        "scan_time": "2026-09-23 18:35:00",
        "file_info": metadata,
        "static_analysis": metadata,
        "ai_analysis": ai_res,
        "cloud_analysis": cloud_res,
        "hybrid_decision": {
            "final_verdict": final_verdict,
            "overall_risk_score": risk_score,
            "risk_percentage": f"{round(risk_score * 100, 1)}%",
            "applied_rule": "Cloud Threat Consensus (Đám mây xác thực cao)",
            "verdict_explanation": f"Phát hiện bởi {cloud_res['positives']}/{cloud_res['total']} hãng bảo mật hàng đầu. Phân loại: {cloud_res.get('threat_classification')}."
        },
        "remediation": remediation
    }

def _generate_mock_zeroday_report(detector, demo_info):
    import numpy as np
    sha256 = "c89b7a42168f12a4b89230571de445903b4129e0ab854129e0ab859871ef3321"
    cloud_res = {
        "status": "NOT_FOUND",
        "positives": 0,
        "total": 0,
        "cloud_score": 0.0,
        "threat_classification": "Tệp hoàn toàn mới (Chưa có chữ ký mẫu trên Cloud)",
        "top_detections": {},
        "source": "VirusTotal (Hash Not Found - Zero-Day Candidate)"
    }

    # Vector 20 đặc trưng mô phỏng mã độc nén Zero-Day
    feat_vector = np.array([
        185400, 3, 7.84, 7.95, 2, 8, 1, 2, 2, 1, 2, 1,
        258, 0, 2, 60000, 5400, 4096, 61440, 0
    ], dtype=np.float32)
    ai_res = detector.ai.predict(feat_vector)

    metadata = {
        "filename": "Unknown_Invoice_Drop.exe",
        "file_size": 185400,
        "is_pe": True,
        "md5": "a3b98c764e101f359b8a21ce904724bc",
        "sha1": "71bce892304918efba20394812fce0983291abfe",
        "sha256": sha256,
        "imphash": "f34d5f2d4577ed6d",
        "overall_entropy": 7.84,
        "max_section_entropy": 7.95,
        "num_sections": 3,
        "num_imported_dlls": 2,
        "num_imported_funcs": 8,
        "has_suspicious_section": True,
        "size_anomaly_count": 2,
        "sections": [
            {"name": "UPX0", "virtual_size": 120000, "raw_size": 0, "entropy": 0.0, "is_suspicious": True},
            {"name": "UPX1", "virtual_size": 60000, "raw_size": 58000, "entropy": 7.95, "is_suspicious": True},
            {"name": ".rsrc", "virtual_size": 5400, "raw_size": 5000, "entropy": 5.40, "is_suspicious": False}
        ],
        "suspicious_apis": {
            "injection": ["virtualalloc", "virtualprotect"],
            "persistence": ["regsetvalueexa"],
            "evasion": ["isdebuggerpresent", "gettickcount"],
            "network": ["urldownloadtofilea"],
            "execution": ["winexec"],
            "spying": []
        }
    }

    final_verdict = "SUSPICIOUS_UNKNOWN"
    risk_score = ai_res["ai_confidence"]
    remediation = detector_remediation_gen(metadata, ai_res, cloud_res, final_verdict, risk_score)

    return {
        "scan_time": "2026-09-23 18:35:00",
        "file_info": metadata,
        "static_analysis": metadata,
        "ai_analysis": ai_res,
        "cloud_analysis": cloud_res,
        "hybrid_decision": {
            "final_verdict": final_verdict,
            "overall_risk_score": risk_score,
            "risk_percentage": f"{round(risk_score * 100, 1)}%",
            "applied_rule": "Local AI Heuristics (Zero-Day Anomaly Detection)",
            "verdict_explanation": "Tệp hoàn toàn mới trên Cloud nhưng chứa các đặc trưng nén mã độc (UPX), entropy cao và API can thiệp bộ nhớ nhạy cảm."
        },
        "remediation": remediation
    }

def _generate_mock_benign_report(detector, demo_info):
    import numpy as np
    sha256 = "8f14e45fceea167a5a36dedd4bea25432352526549863ac1b12baf66db537119"
    cloud_res = {
        "status": "FOUND",
        "positives": 0,
        "total": 73,
        "cloud_score": 0.0,
        "threat_classification": "Clean Binary (An toàn - Đã xác thực)",
        "top_detections": {},
        "source": "VirusTotal Cloud Verified"
    }

    # Vector 20 đặc trưng mô phỏng tệp sạch (có ASLR, DEP, chữ ký số hợp lệ)
    feat_vector = np.array([
        57344, 3, 0.04, 0.0, 1, 1, 0, 0, 0, 0, 0, 0,
        8450, 34112, 3, 25600, 2048, 8192, 33694, 1
    ], dtype=np.float32)
    ai_res = detector.ai.predict(feat_vector)

    metadata = {
        "filename": "calc_clean_utility.exe",
        "file_size": 450560,
        "is_pe": True,
        "md5": "c4ca4238a0b923820dcc509a6f75849b",
        "sha1": "70b8c4c77c152e2f384a86f03126f5367a737f19",
        "sha256": sha256,
        "imphash": "d41d8cd98f00b204e9800998ecf8427e",
        "overall_entropy": 5.82,
        "max_section_entropy": 6.45,
        "num_sections": 6,
        "num_imported_dlls": 12,
        "num_imported_funcs": 142,
        "has_suspicious_section": False,
        "size_anomaly_count": 0,
        "sections": [
            {"name": ".text", "virtual_size": 240000, "raw_size": 241664, "entropy": 6.45, "is_suspicious": False},
            {"name": ".rdata", "virtual_size": 95000, "raw_size": 96256, "entropy": 5.72, "is_suspicious": False},
            {"name": ".data", "virtual_size": 18000, "raw_size": 12288, "entropy": 3.42, "is_suspicious": False},
            {"name": ".pdata", "virtual_size": 14000, "raw_size": 14336, "entropy": 4.10, "is_suspicious": False},
            {"name": ".rsrc", "virtual_size": 75000, "raw_size": 75776, "entropy": 5.12, "is_suspicious": False},
            {"name": ".reloc", "virtual_size": 8000, "raw_size": 8192, "entropy": 2.15, "is_suspicious": False}
        ],
        "suspicious_apis": {
            "injection": [],
            "persistence": [],
            "evasion": [],
            "network": [],
            "execution": [],
            "spying": []
        }
    }

    final_verdict = "BENIGN"
    risk_score = 0.05
    remediation = detector_remediation_gen(metadata, ai_res, cloud_res, final_verdict, risk_score)

    return {
        "scan_time": "2026-09-23 18:35:00",
        "file_info": metadata,
        "static_analysis": metadata,
        "ai_analysis": ai_res,
        "cloud_analysis": cloud_res,
        "hybrid_decision": {
            "final_verdict": final_verdict,
            "overall_risk_score": risk_score,
            "risk_percentage": f"{round(risk_score * 100, 1)}%",
            "applied_rule": "Cloud & AI Verified Clean",
            "verdict_explanation": "Tệp sạch tiêu chuẩn được xác thực bởi cả đám mây và mô hình AI phân tích tĩnh tại chỗ."
        },
        "remediation": remediation
    }

def detector_remediation_gen(metadata, ai_res, cloud_res, final_verdict, risk_score):
    from remediation_engine import RemediationEngine
    return RemediationEngine.generate_playbook(
        target_file=metadata["filename"],
        metadata=metadata,
        ai_analysis=ai_res,
        cloud_analysis=cloud_res,
        final_verdict=final_verdict,
        risk_score=risk_score
    )

@app.route("/api/download-script", methods=["POST"])
def download_script():
    script_content = request.json.get("script", "")
    filename = request.json.get("filename", "remediation_script.ps1")
    return Response(
        script_content,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@app.route("/api/models/comparison", methods=["GET"])
def get_models_comparison():
    rf_json_path = os.path.join("RandomForest", "result", "metrics_summary.json")
    knn_json_path = os.path.join("KNN", "result", "metrics_summary.json")
    svm_json_path = os.path.join("SVM", "result", "metrics_summary.json")
    
    rf_data = {}
    knn_data = {}
    svm_data = {}
    if os.path.exists(rf_json_path):
        with open(rf_json_path, "r", encoding="utf-8") as f:
            rf_data = json.load(f)
    if os.path.exists(knn_json_path):
        with open(knn_json_path, "r", encoding="utf-8") as f:
            knn_data = json.load(f)
    if os.path.exists(svm_json_path):
        with open(svm_json_path, "r", encoding="utf-8") as f:
            svm_data = json.load(f)
            
    return jsonify({
        "status": "success",
        "models": {
            "Random Forest": rf_data.get("performance_metrics", {}),
            "K-Nearest Neighbors (KNN)": knn_data.get("performance_metrics", {}),
            "Support Vector Machine (SVM)": svm_data.get("performance_metrics", {})
        },
        "confusion_matrix": {
            "Random Forest": rf_data.get("confusion_matrix", {}),
            "K-Nearest Neighbors (KNN)": knn_data.get("confusion_matrix", {}),
            "Support Vector Machine (SVM)": svm_data.get("confusion_matrix", {})
        },
        "roc_curve": {
            "Random Forest": rf_data.get("roc_curve", {}),
            "K-Nearest Neighbors (KNN)": knn_data.get("roc_curve", {}),
            "Support Vector Machine (SVM)": svm_data.get("roc_curve", {})
        }
    })

if __name__ == "__main__":
    print("Khởi chạy Web Dashboard Hệ thống Phát hiện Mã độc Lai tại http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
