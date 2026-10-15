import os
import sys
import io
import time
import json
import joblib
import numpy as np
import pandas as pd

# Thiết lập encoding UTF-8 để hiển thị tiếng Việt trên console Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Thư viện Machine Learning & Đo lường
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, log_loss, confusion_matrix, classification_report,
    roc_curve
)

# Thư viện trực quan hóa
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

# Xác định đường dẫn thư mục gốc và thư mục kết quả riêng của RandomForest
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..")) if os.path.basename(CURRENT_DIR) == "RandomForest" else CURRENT_DIR
RESULT_DIR = os.path.join(CURRENT_DIR, "result")

FEATURE_NAMES = [
    "file_size", "num_sections", "overall_entropy", "max_sec_entropy",
    "num_imported_dlls", "num_imported_funcs", "has_suspicious_section",
    "size_anomaly_count", "count_injection_apis", "count_persistence_apis",
    "count_evasion_apis", "count_network_apis",
    "characteristics", "dll_characteristics", "subsystem",
    "size_of_code", "size_of_init_data", "base_of_code",
    "address_entry_point", "has_security_cert"
]

FEATURE_LABELS_VN = {
    "file_size": "Kích thước tệp (SizeOfImage)",
    "num_sections": "Số lượng Section",
    "overall_entropy": "Entropy trung bình",
    "max_sec_entropy": "Entropy Section cao nhất",
    "num_imported_dlls": "Số lượng DLL nạp",
    "num_imported_funcs": "Số lượng API nạp",
    "has_suspicious_section": "Tên Section đáng ngờ",
    "size_anomaly_count": "Bất thường RAM vs Đĩa",
    "count_injection_apis": "API tiêm nhiễm bộ nhớ",
    "count_persistence_apis": "API duy trì khởi động",
    "count_evasion_apis": "API né tránh phòng thủ",
    "count_network_apis": "API kết nối mạng C2",
    "characteristics": "Cờ thuộc tính PE (Characteristics)",
    "dll_characteristics": "Cờ an ninh (DllCharacteristics: ASLR/DEP)",
    "subsystem": "Hệ thống con (Subsystem: GUI/Console)",
    "size_of_code": "Kích thước vùng mã lệnh (SizeOfCode)",
    "size_of_init_data": "Kích thước dữ liệu khởi tạo",
    "base_of_code": "Địa chỉ cơ sở mã lệnh (BaseOfCode)",
    "address_entry_point": "Điểm bắt đầu thực thi (AddressOfEntryPoint)",
    "has_security_cert": "Chứng thực chữ ký số (Certificate)"
}

def load_dataset():
    """Tải và ánh xạ dữ liệu 20 đặc trưng từ thư mục data/ của dự án."""
    dataset_path = os.path.join(ROOT_DIR, "data", "dataset_malwares.csv")
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"[!] Không tìm thấy tệp dữ liệu: {dataset_path}")

    print(f"[*] Đang đọc tập dữ liệu từ: {dataset_path} ...")
    df = pd.read_csv(dataset_path)

    def extract_df_features(data_df):
        X_df = pd.DataFrame()
        X_df['file_size'] = data_df['SizeOfImage']
        X_df['num_sections'] = data_df['NumberOfSections']
        X_df['overall_entropy'] = (data_df['SectionMinEntropy'] + data_df['SectionMaxEntropy']) / 2
        X_df['max_sec_entropy'] = data_df['SectionMaxEntropy']
        X_df['num_imported_dlls'] = data_df['DirectoryEntryImport']
        X_df['num_imported_funcs'] = data_df['DirectoryEntryImportSize'] if 'DirectoryEntryImportSize' in data_df.columns else data_df['DirectoryEntryImport'] * 5
        X_df['has_suspicious_section'] = data_df['SuspiciousNameSection']
        X_df['size_anomaly_count'] = (data_df['SectionMaxVirtualsize'] > data_df['SectionMaxRawsize']).astype(int)
        X_df['count_injection_apis'] = (data_df['SuspiciousImportFunctions'] / 3).astype(int)
        X_df['count_persistence_apis'] = (data_df['SuspiciousImportFunctions'] / 4).astype(int)
        X_df['count_evasion_apis'] = (data_df['SuspiciousImportFunctions'] / 4).astype(int)
        X_df['count_network_apis'] = (data_df['SuspiciousImportFunctions'] / 5).astype(int)
        # 8 Đặc trưng PE Header nâng cao
        X_df['characteristics'] = data_df['Characteristics']
        X_df['dll_characteristics'] = data_df['DllCharacteristics']
        X_df['subsystem'] = data_df['Subsystem']
        X_df['size_of_code'] = data_df['SizeOfCode']
        X_df['size_of_init_data'] = data_df['SizeOfInitializedData']
        X_df['base_of_code'] = data_df['BaseOfCode']
        X_df['address_entry_point'] = data_df['AddressOfEntryPoint']
        X_df['has_security_cert'] = (data_df['ImageDirectoryEntrySecurity'] > 0).astype(int) if 'ImageDirectoryEntrySecurity' in data_df.columns else 0
        return X_df.values.astype(np.float32)

    X = extract_df_features(df)
    y = df['Malware'].values.astype(int)

    # Gộp thêm dữ liệu tệp sạch nếu có
    for extra_rel in ["data/benign_dataset.csv", "extra_benign_dataset.csv"]:
        extra_path = os.path.join(ROOT_DIR, extra_rel)
        if os.path.exists(extra_path):
            try:
                df_b = pd.read_csv(extra_path)
                X_b = extract_df_features(df_b)
                X = np.vstack((X, X_b))
                y = np.concatenate((y, np.zeros(len(df_b), dtype=int)))
                print(f"[+] Đã gộp thêm {len(df_b)} mẫu sạch từ: {extra_rel}")
            except Exception as e:
                print(f"[-] Bỏ qua {extra_rel}: {e}")

    return X, y

def plot_and_save_charts(y_test, y_pred, y_proba, rf_model, output_dir):
    """Vẽ và lưu trữ biểu đồ trực quan hóa kết quả vào thư mục result của RandomForest."""
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')

    # 1. Vẽ Ma trận nhầm lẫn (Confusion Matrix)
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(7, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False,
                xticklabels=['Sạch (Benign)', 'Mã độc (Malware)'],
                yticklabels=['Sạch (Benign)', 'Mã độc (Malware)'],
                annot_kws={"size": 14, "weight": "bold"})
    plt.title('Ma Trận Nhầm Lẫn - Random Forest', fontsize=13, fontweight='bold', pad=15)
    plt.xlabel('Nhãn Dự Đoán (Predicted Label)', fontsize=11)
    plt.ylabel('Nhãn Thực Tế (Ground Truth)', fontsize=11)
    plt.tight_layout()
    cm_path = os.path.join(output_dir, "confusion_matrix.png")
    plt.savefig(cm_path, dpi=300)
    plt.close()

    # 2. Vẽ Đường cong ROC
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    auc_score = roc_auc_score(y_test, y_proba)
    plt.figure(figsize=(7, 6))
    plt.plot(fpr, tpr, color='#1f77b4', lw=2.5, label=f'Random Forest (AUC = {auc_score:.4f})')
    plt.plot([0, 1], [0, 1], color='#e74c3c', lw=1.5, linestyle='--', label='Ngẫu nhiên (AUC = 0.50)')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Tỷ Lệ Báo Động Nhầm (FPR)', fontsize=11)
    plt.ylabel('Tỷ Lệ Phát Hiện Đúng (Recall)', fontsize=11)
    plt.title('Đường Cong ROC - Random Forest', fontsize=13, fontweight='bold', pad=15)
    plt.legend(loc="lower right", fontsize=11)
    plt.tight_layout()
    roc_path = os.path.join(output_dir, "roc_curve.png")
    plt.savefig(roc_path, dpi=300)
    plt.close()

    # 3. Vẽ Độ quan trọng của các đặc trưng (Feature Importances)
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1]
    sorted_labels = [FEATURE_LABELS_VN.get(FEATURE_NAMES[i], FEATURE_NAMES[i]) for i in indices]
    sorted_values = importances[indices]

    plt.figure(figsize=(10, 6))
    bars = plt.barh(range(len(sorted_labels)), sorted_values[::-1], color='#2ecc71', edgecolor='#27ae60', height=0.65)
    plt.yticks(range(len(sorted_labels)), sorted_labels[::-1], fontsize=10)
    plt.xlabel('Mức Độ Đóng Góp (Importance Score)', fontsize=11)
    plt.title('Độ Quan Trọng Của Đặc Trưng - Random Forest', fontsize=13, fontweight='bold', pad=15)
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.005, bar.get_y() + bar.get_height()/2, f"{width*100:.1f}%",
                 va='center', ha='left', fontsize=9, color='#2c3e50', fontweight='bold')

    plt.xlim(0, max(sorted_values) * 1.18)
    plt.tight_layout()
    feat_path = os.path.join(output_dir, "feature_importance.png")
    plt.savefig(feat_path, dpi=300)
    plt.close()

def main():
    print("==================================================================")
    print("        HUẤN LUYỆN VÀ ĐÁNH GIÁ THUẬT TOÁN RANDOM FOREST           ")
    print("==================================================================")

    # 1. Tạo thư mục result bên trong thư mục RandomForest
    os.makedirs(RESULT_DIR, exist_ok=True)
    print(f"[*] Thư mục lưu kết quả: {RESULT_DIR}")

    # 2. Nạp dữ liệu
    X, y = load_dataset()
    total_samples = len(y)
    num_malware = int(np.sum(y == 1))
    num_benign = int(np.sum(y == 0))
    print(f"[*] Tổng số mẫu: {total_samples:,} (Mã độc: {num_malware:,}, Sạch: {num_benign:,})")

    # 3. Phân chia Train/Test
    test_ratio = 0.2
    random_seed = 42
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_ratio, random_state=random_seed, stratify=y
    )
    print(f"[*] Tập Train: {len(y_train):,} mẫu | Tập Test: {len(y_test):,} mẫu")

    # 4. Siêu tham số & Pipeline
    n_estimators = 100
    max_depth = 12
    cpu_jobs = -1

    hyperparams = {
        "algorithm": "RandomForestClassifier",
        "n_estimators": n_estimators,
        "max_depth": max_depth,
        "n_jobs": cpu_jobs,
        "random_state": random_seed,
        "test_size": test_ratio,
        "scaler": "StandardScaler"
    }

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            n_jobs=cpu_jobs,
            random_state=random_seed
        ))
    ])

    # 5. Huấn luyện
    print(f"[*] Đang huấn luyện Random Forest (Đa nhân CPU n_jobs={cpu_jobs})...")
    start_train = time.time()
    pipeline.fit(X_train, y_train)
    train_duration = time.time() - start_train
    print(f"[+] Thời gian huấn luyện: {train_duration:.2f} giây")

    # 6. Dự đoán & Đo lường
    print("[*] Đang đánh giá trên tập kiểm thử (Inference)...")
    start_infer = time.time()
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    infer_duration = time.time() - start_infer
    latency_per_sample_ms = (infer_duration / len(X_test)) * 1000

    # 7. Tính Metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    loss = log_loss(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    report_str = classification_report(
        y_test, y_pred,
        target_names=["Sạch (Benign)", "Mã độc (Malware)"],
        digits=4
    )

    print("\n" + "=" * 66)
    print("                 KẾT QUẢ RANDOM FOREST                          ")
    print("=" * 66)
    print(f">> Độ chính xác tổng thể (Accuracy) : {acc * 100:.2f}%")
    print(f">> Độ chuẩn xác (Precision)         : {prec * 100:.2f}%")
    print(f">> Độ bao phủ (Recall / Sensitivity): {rec * 100:.2f}%")
    print(f">> Điểm F1-Score                   : {f1 * 100:.2f}%")
    print(f">> Diện tích dưới đường cong ROC-AUC: {auc:.4f}")
    print(f">> Hàm mất mát (Log Loss / Cost)   : {loss:.4f}")
    print(f">> Độ trễ dự đoán trung bình        : {latency_per_sample_ms:.4f} ms / mẫu")
    print(f">> Ma trận nhầm lẫn                 : TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print("=" * 66)

    # 8. Lưu kết quả vào thư mục RandomForest/result/
    # Model
    model_path = os.path.join(RESULT_DIR, "random_forest_model.pkl")
    joblib.dump(pipeline, model_path)
    # Đồng bộ ra models/ chính
    models_dir = os.path.join(ROOT_DIR, "models")
    os.makedirs(models_dir, exist_ok=True)
    joblib.dump(pipeline, os.path.join(models_dir, "malware_rf_model.pkl"))

    # Báo cáo text
    with open(os.path.join(RESULT_DIR, "classification_report.txt"), "w", encoding="utf-8") as f:
        f.write("BÁO CÁO KẾT QUẢ THUẬT TOÁN RANDOM FOREST\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Accuracy : {acc * 100:.2f}%\nPrecision: {prec * 100:.2f}%\nRecall   : {rec * 100:.2f}%\nF1-Score : {f1 * 100:.2f}%\nROC-AUC  : {auc:.4f}\nLog Loss : {loss:.4f}\nLatency  : {latency_per_sample_ms:.4f} ms/mẫu\n\n")
        f.write(f"BÁO CÁO CHI TIẾT:\n{report_str}\n\n")
        f.write(f"MA TRẬN NHẦM LẪN: TN={tn}, FP={fp}, FN={fn}, TP={tp}\n")

    # JSON
    metrics_data = {
        "algorithm": "RandomForest",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hyperparameters": hyperparams,
        "performance_metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(auc), 4),
            "log_loss": round(float(loss), 4),
            "training_time_seconds": round(float(train_duration), 2),
            "inference_latency_ms_per_sample": round(float(latency_per_sample_ms), 4)
        },
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp)
        }
    }
    with open(os.path.join(RESULT_DIR, "metrics_summary.json"), "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, ensure_ascii=False, indent=4)

    # Đối chiếu mẫu
    sample_df = pd.DataFrame({
        "Ground_Truth": y_test[:100],
        "Prediction": y_pred[:100],
        "Malware_Probability": np.round(y_proba[:100], 4),
        "Is_Correct": (y_test[:100] == y_pred[:100])
    })
    sample_df.to_csv(os.path.join(RESULT_DIR, "predictions_sample.csv"), index=False)

    # Biểu đồ
    plot_and_save_charts(y_test, y_pred, y_proba, pipeline.named_steps["rf"], RESULT_DIR)

    print(f"\n[SUCCESS] Toàn bộ kết quả đã được lưu tại: {RESULT_DIR}")

if __name__ == "__main__":
    main()
