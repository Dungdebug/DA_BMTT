import sys
import io
import os

# Cấu hình lại stdout để in được tiếng Việt trên console Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from ai_engine import AIEngine
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

def main():
    print("==================================================")
    print("   BẮT ĐẦU QUÁ TRÌNH HUẤN LUYỆN AI (KAGGLE DATA)   ")
    print("==================================================")
    
    # Tạo đối tượng engine nhưng không gọi __init__ để tránh auto-train
    engine = AIEngine.__new__(AIEngine)
    X, y = engine._load_kaggle_dataset()
    
    # Chia tập dữ liệu: 80% để train, 20% để test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"[*] Tổng số mẫu: {len(y)}")
    print(f"[*] Số mẫu để Train: {len(y_train)}")
    print(f"[*] Số mẫu để Test: {len(y_test)}")
    
    # Tạo pipeline chuẩn hóa và huấn luyện
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)) # Tăng max_depth vì dữ liệu lớn hơn
    ])
    
    print("\n[*] Đang tiến hành huấn luyện (Training) mô hình Random Forest...")
    pipeline.fit(X_train, y_train)
    
    print("[*] Đang đánh giá độ chính xác trên tập Test...")
    y_pred = pipeline.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["Sạch (Benign)", "Mã độc (Malicious)"])
    
    print("\n================ KẾT QUẢ HUẤN LUYỆN ================")
    print(f">> ĐỘ CHÍNH XÁC TỔNG THỂ (Accuracy): {acc * 100:.2f}%\n")
    print(">> BÁO CÁO CHI TIẾT:")
    print(report)
    print("====================================================")
    
    # Lưu mô hình
    model_path = "models/malware_rf_model.pkl"
    joblib.dump(pipeline, model_path)
    print(f"[+] Đã lưu mô hình mới tại: {model_path}")
    print("[+] AI đã sẵn sàng để phát hiện mã độc!")

if __name__ == "__main__":
    main()
