import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

MODEL_FILE = "malware_rf_model.pkl"

class AIEngine:
    FEATURE_NAMES = [
        "file_size", "num_sections", "overall_entropy", "max_sec_entropy",
        "num_imported_dlls", "num_imported_funcs", "has_suspicious_section",
        "size_anomaly_count", "count_injection_apis", "count_persistence_apis",
        "count_evasion_apis", "count_network_apis"
    ]

    def __init__(self):
        self.model = self._load_or_create_model()

    def _generate_synthetic_dataset(self):
        """
        Sinh tập dữ liệu mẫu đại diện cho phân phối đặc trưng thực tế của:
        - 0: File sạch (Benign)
        - 1: File mã độc (Malicious)
        - Hỗ trợ học các pattern tinh vi: packed, memory injection, evasion, trojan dropper.
        """
        np.random.seed(42)
        X = []
        y = []

        # 1. Nhóm Benign (60 mẫu)
        # Đặc trưng: Entropy vừa phải (4.5 - 6.5), nhiều DLL & hàm thông dụng, không có section lạ
        for _ in range(60):
            size = np.random.randint(50_000, 5_000_000)
            sections = np.random.randint(3, 8)
            overall_ent = np.random.uniform(4.2, 6.4)
            max_sec_ent = min(8.0, overall_ent + np.random.uniform(0.1, 0.6))
            dlls = np.random.randint(5, 25)
            funcs = np.random.randint(40, 300)
            has_sus_sec = 0
            size_anomaly = 0
            # File sạch hiếm khi gọi API tiêm nhiễm hoặc anti-debug cùng lúc
            inj = np.random.choice([0, 1], p=[0.9, 0.1])
            pers = np.random.choice([0, 1], p=[0.85, 0.15])
            evas = np.random.choice([0, 1], p=[0.85, 0.15])
            net = np.random.choice([0, 1, 2], p=[0.75, 0.2, 0.05])
            X.append([size, sections, overall_ent, max_sec_ent, dlls, funcs, has_sus_sec, size_anomaly, inj, pers, evas, net])
            y.append(0)

        # 2. Nhóm Malicious - Packed / Crypter (35 mẫu)
        # Đặc trưng: Entropy cực cao (>7.2), ít hàm/DLL do bị giấu, có packer section hoặc size anomaly
        for _ in range(35):
            size = np.random.randint(30_000, 800_000)
            sections = np.random.randint(2, 6)
            overall_ent = np.random.uniform(7.1, 7.95)
            max_sec_ent = np.random.uniform(7.4, 7.99)
            dlls = np.random.randint(1, 4)
            funcs = np.random.randint(2, 20)
            has_sus_sec = np.random.choice([0, 1], p=[0.3, 0.7])
            size_anomaly = np.random.choice([1, 2, 3], p=[0.4, 0.4, 0.2])
            inj = np.random.randint(1, 4)
            pers = np.random.choice([0, 1, 2], p=[0.4, 0.4, 0.2])
            evas = np.random.randint(1, 4)
            net = np.random.choice([0, 1, 2], p=[0.4, 0.4, 0.2])
            X.append([size, sections, overall_ent, max_sec_ent, dlls, funcs, has_sus_sec, size_anomaly, inj, pers, evas, net])
            y.append(1)

        # 3. Nhóm Malicious - Trojan Dropper / Spyware / Ransomware (35 mẫu)
        # Đặc trưng: Có thể không pack nhưng gọi ồ ạt API tiêm nhiễm, duy trì khởi động, mạng và né tránh debugger
        for _ in range(35):
            size = np.random.randint(80_000, 2_000_000)
            sections = np.random.randint(3, 7)
            overall_ent = np.random.uniform(6.2, 7.4)
            max_sec_ent = np.random.uniform(6.6, 7.7)
            dlls = np.random.randint(3, 10)
            funcs = np.random.randint(25, 90)
            has_sus_sec = np.random.choice([0, 1], p=[0.7, 0.3])
            size_anomaly = np.random.choice([0, 1], p=[0.7, 0.3])
            inj = np.random.randint(2, 6)
            pers = np.random.randint(1, 4)
            evas = np.random.randint(1, 4)
            net = np.random.randint(1, 4)
            X.append([size, sections, overall_ent, max_sec_ent, dlls, funcs, has_sus_sec, size_anomaly, inj, pers, evas, net])
            y.append(1)

        return np.array(X, dtype=np.float32), np.array(y, dtype=int)

    def _load_or_create_model(self):
        """Khởi tạo hoặc tải mô hình RandomForest với Pipeline chuẩn hóa."""
        if os.path.exists(MODEL_FILE):
            try:
                pipeline = joblib.load(MODEL_FILE)
                # Kiểm tra tương thích số lượng đặc trưng
                if hasattr(pipeline, "n_features_in_") and pipeline.n_features_in_ == len(self.FEATURE_NAMES):
                    return pipeline
            except Exception:
                pass

        # Huấn luyện mô hình chuẩn
        X, y = self._generate_synthetic_dataset()
        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("rf", RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42))
        ])
        pipeline.fit(X, y)
        joblib.dump(pipeline, MODEL_FILE)
        return pipeline

    def explain_features(self, feature_vector):
        """
        Explainable AI (XAI): Phân tích và đưa ra các lý do khả nghi giải thích tại sao file bị đánh giá rủi ro.
        """
        reasons = []
        feat = feature_vector

        # feat index:
        # 0: size, 1: sections, 2: overall_entropy, 3: max_sec_entropy,
        # 4: dlls, 5: funcs, 6: has_sus_sec, 7: size_anomaly,
        # 8: inj, 9: pers, 10: evas, 11: net

        if feat[2] >= 7.2 or feat[3] >= 7.5:
            reasons.append({
                "severity": "HIGH",
                "tag": "High Entropy / Obfuscation",
                "detail": f"Độ hỗn loạn entropy rất cao (Toàn file: {feat[2]:.2f}, Section max: {feat[3]:.2f}/8.0). Dấu hiệu đặc trưng của file bị nén (packed) hoặc mã hóa để giấu mã độc."
            })

        if feat[6] > 0:
            reasons.append({
                "severity": "HIGH",
                "tag": "Suspicious Section Header",
                "detail": "Phát hiện tên Section đặc trưng của các công cụ đóng gói phần mềm độc hại (UPX, Themida, ASPack...)."
            })

        if feat[7] > 0:
            reasons.append({
                "severity": "MEDIUM",
                "tag": "Size Anomaly / Memory Unpacking",
                "detail": f"Phát hiện {int(feat[7])} section có kích thước ảo trong bộ nhớ lớn bất thường so với dữ liệu trên đĩa (VirtualSize >> RawSize), dấu hiệu giải nén mã lệnh trực tiếp vào RAM khi chạy."
            })

        if feat[8] > 0:
            reasons.append({
                "severity": "CRITICAL" if feat[8] >= 2 else "HIGH",
                "tag": "Process Injection / Memory Tampering",
                "detail": f"Phát hiện {int(feat[8])} hàm API can thiệp bộ nhớ sâu (VirtualAlloc, WriteProcessMemory, CreateRemoteThread...), thường dùng để chèn shellcode vào tiến trình hệ thống."
            })

        if feat[9] > 0:
            reasons.append({
                "severity": "HIGH",
                "tag": "Persistence Mechanism",
                "detail": f"Phát hiện {int(feat[9])} hàm API ghi khóa Registry hoặc cài đặt Windows Service nhằm tự khởi động cùng hệ điều hành."
            })

        if feat[10] > 0:
            reasons.append({
                "severity": "MEDIUM",
                "tag": "Anti-Analysis & Evasion",
                "detail": f"Phát hiện {int(feat[10])} hàm API kiểm tra Debugger / máy ảo (IsDebuggerPresent, CheckRemoteDebugger...) nhằm lẩn tránh các phần mềm diệt virus."
            })

        if feat[11] > 0:
            reasons.append({
                "severity": "MEDIUM",
                "tag": "C2 Communication / Dropper",
                "detail": f"Phát hiện {int(feat[11])} hàm API kết nối mạng và tải tệp từ xa (URLDownloadToFile, HttpSendRequest, socket...)."
            })

        if feat[4] <= 2 and feat[5] <= 15 and feat[2] > 6.8:
            reasons.append({
                "severity": "MEDIUM",
                "tag": "Hidden Imports (Statically Stripped)",
                "detail": "Số lượng hàm và DLL import ít bất thường kết hợp entropy cao, chứng tỏ bảng Import đã bị che giấu để gây khó khăn cho việc phân tích tĩnh."
            })

        return reasons

    def predict(self, feature_vector):
        """
        Dự đoán xác suất và phân loại:
        - BENIGN: An toàn
        - SUSPICIOUS_UNKNOWN: File lạ / Nghi vấn bất thường (Zero-day Heuristics)
        - MALICIOUS: Độc hại
        """
        features_reshaped = feature_vector.reshape(1, -1)
        prob = self.model.predict_proba(features_reshaped)[0][1]
        reasons = self.explain_features(feature_vector)

        # Phân loại trạng thái AI
        if prob >= 0.65:
            label = "MALICIOUS"
            classification_desc = "Tệp mang nhiều đặc trưng nguy hại đã được nhận diện"
        elif prob >= 0.35 or len(reasons) >= 2 or feature_vector[6] > 0 or feature_vector[7] > 0:
            label = "SUSPICIOUS_UNKNOWN"
            classification_desc = "Tệp lạ / Nghi vấn bất thường (Có thể là biến thể mới hoặc Zero-Day)"
        else:
            label = "BENIGN"
            classification_desc = "Tệp mang cấu trúc chuẩn và đặc trưng an toàn"

        return {
            "ai_confidence": round(float(prob), 4),
            "ai_label": label,
            "classification_desc": classification_desc,
            "xai_reasons": reasons
        }