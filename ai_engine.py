import os
import joblib
import numpy as np
import pandas as pd
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

    def _load_kaggle_dataset(self):
        """
        Đọc dữ liệu thật từ file dataset_malwares.csv của Kaggle.
        Ánh xạ (map) các cột tương ứng với FEATURE_NAMES của AI.
        """
        import pandas as pd
        dataset_path = "dataset_malwares.csv"
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Không tìm thấy file {dataset_path}. Vui lòng tải về thư mục dự án.")

        print("[*] Đang tải tập dữ liệu Kaggle Malware Detection...")
        df = pd.read_csv(dataset_path)
        
        # Map các cột từ Kaggle dataset sang 12 features của chúng ta
        X_mapped = pd.DataFrame()
        X_mapped['file_size'] = df['SizeOfImage']
        X_mapped['num_sections'] = df['NumberOfSections']
        
        # Giả lập overall_entropy từ trung bình của SectionMin và SectionMax
        X_mapped['overall_entropy'] = df['SectionMinEntropy'] + (df['SectionMaxEntropy'] - df['SectionMinEntropy']) / 2
        X_mapped['max_sec_entropy'] = df['SectionMaxEntropy']
        
        X_mapped['num_imported_dlls'] = df['DirectoryEntryImport']
        X_mapped['num_imported_funcs'] = df['DirectoryEntryImportSize'] if 'DirectoryEntryImportSize' in df.columns else df['DirectoryEntryImport'] * 5
        X_mapped['has_suspicious_section'] = df['SuspiciousNameSection']
        
        # Kiểm tra nếu dung lượng ảo lớn hơn dung lượng thực tế
        X_mapped['size_anomaly_count'] = (df['SectionMaxVirtualsize'] > df['SectionMaxRawsize']).astype(int)
        
        # Chia các hàm import đáng ngờ thành các nhóm API (tiêm nhiễm, né tránh...)
        X_mapped['count_injection_apis'] = (df['SuspiciousImportFunctions'] / 3).astype(int)
        X_mapped['count_persistence_apis'] = (df['SuspiciousImportFunctions'] / 4).astype(int)
        X_mapped['count_evasion_apis'] = (df['SuspiciousImportFunctions'] / 4).astype(int)
        X_mapped['count_network_apis'] = (df['SuspiciousImportFunctions'] / 5).astype(int)
        
        X = X_mapped.values.astype(np.float32)
        y = df['Malware'].values.astype(int)
        print(f"[*] Đã tải xong {len(df)} mẫu dữ liệu gốc!")
        
        # CƠ CHẾ MỚI: Hỗ trợ nạp thêm dữ liệu tệp sạch (Benign) để huấn luyện cùng
        extra_benign_path = "extra_benign_dataset.csv"
        if os.path.exists(extra_benign_path):
            print(f"[*] Đang gộp thêm dữ liệu tệp sạch từ {extra_benign_path}...")
            df_b = pd.read_csv(extra_benign_path)
            
            X_b = pd.DataFrame()
            X_b['file_size'] = df_b['SizeOfImage']
            X_b['num_sections'] = df_b['NumberOfSections']
            X_b['overall_entropy'] = df_b['SectionMinEntropy'] + (df_b['SectionMaxEntropy'] - df_b['SectionMinEntropy']) / 2
            X_b['max_sec_entropy'] = df_b['SectionMaxEntropy']
            X_b['num_imported_dlls'] = df_b['DirectoryEntryImport']
            X_b['num_imported_funcs'] = df_b['DirectoryEntryImportSize'] if 'DirectoryEntryImportSize' in df_b.columns else df_b['DirectoryEntryImport'] * 5
            X_b['has_suspicious_section'] = df_b['SuspiciousNameSection']
            X_b['size_anomaly_count'] = (df_b['SectionMaxVirtualsize'] > df_b['SectionMaxRawsize']).astype(int)
            X_b['count_injection_apis'] = (df_b['SuspiciousImportFunctions'] / 3).astype(int)
            X_b['count_persistence_apis'] = (df_b['SuspiciousImportFunctions'] / 4).astype(int)
            X_b['count_evasion_apis'] = (df_b['SuspiciousImportFunctions'] / 4).astype(int)
            X_b['count_network_apis'] = (df_b['SuspiciousImportFunctions'] / 5).astype(int)
            
            X = np.vstack((X, X_b.values.astype(np.float32)))
            # Dán nhãn 0 (File sạch) cho toàn bộ các file trong tập dữ liệu phụ này
            y_b = np.zeros(len(df_b), dtype=int) 
            y = np.concatenate((y, y_b))
            print(f"[*] Đã trộn thành công thêm {len(df_b)} mẫu tệp sạch. Tổng số mẫu hiện tại: {len(y)}")
            
        return X, y

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
        X, y = self._load_kaggle_dataset()
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