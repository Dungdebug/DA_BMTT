import pandas as pd

try:
    df = pd.read_csv('dataset_malwares.csv')
    if 'Malware' in df.columns:
        benign_df = df[df['Malware'] == 0]
        benign_df.to_csv('benign_dataset.csv', index=False)
        print(f"Thành công! Đã trích xuất {len(benign_df)} tệp sạch (Benign) ra file benign_dataset.csv")
    else:
        print("Lỗi: Không tìm thấy cột 'Malware' trong dataset_malwares.csv")
except Exception as e:
    print(f"Lỗi khi xử lý: {e}")
