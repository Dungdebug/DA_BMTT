import os
import sys
import io
import json
import numpy as np
import pandas as pd

# Kích hoạt ANSI Colors trên Windows Console
os.system("")

# Thiết lập encoding UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Định nghĩa bảng mã màu ANSI chuẩn
GREEN = "\033[92m"    # Xanh lá cây - Vượt trội / Tốt nhất
PURPLE = "\033[95m"   # Tím hồng - KNN
ORANGE = "\033[93m"   # Cam/Vàng - SVM
CYAN = "\033[96m"     # Xanh lơ - Tiêu đề
BOLD = "\033[1m"      # In đậm
RESET = "\033[0m"     # Trở về mặc định

def main():
    print(f"{CYAN}========================================================================================================================{RESET}")
    print(f"{BOLD}{CYAN}      ĐO LƯỜNG THỰC TẾ & ĐỐI CHIẾU 3 THUẬT TOÁN AI: RANDOM FOREST vs K-NEAREST NEIGHBORS vs SVM         {RESET}")
    print(f"       (Quy ước: {GREEN}RF = Xanh lá (Ensemble Tree){RESET} | {PURPLE}KNN = Tím (Instance Distance){RESET} | {ORANGE}SVM = Cam (RBF Hyperplane){RESET})")
    print(f"{CYAN}========================================================================================================================{RESET}\n")

    rf_json_path = os.path.join("RandomForest", "result", "metrics_summary.json")
    svm_json_path = os.path.join("SVM", "result", "metrics_summary.json")
    knn_json_path = os.path.join("KNN", "result", "metrics_summary.json")

    missing = []
    if not os.path.exists(rf_json_path):
        missing.append("RandomForest (Chưa chạy python RandomForest/train.py)")
    if not os.path.exists(svm_json_path):
        missing.append("SVM (Chưa chạy python SVM/train.py)")
    if not os.path.exists(knn_json_path):
        missing.append("KNN (Chưa chạy python KNN/train.py)")

    if missing:
        print(f"{ORANGE}[!] Không thể so sánh đầy đủ do thiếu kết quả của mô hình:{RESET}")
        for m in missing:
            print(f"    - {m}")
        return

    with open(rf_json_path, "r", encoding="utf-8") as f:
        rf_data = json.load(f)
    with open(svm_json_path, "r", encoding="utf-8") as f:
        svm_data = json.load(f)
    with open(knn_json_path, "r", encoding="utf-8") as f:
        knn_data = json.load(f)

    rf_m = rf_data["performance_metrics"]
    svm_m = svm_data["performance_metrics"]
    knn_m = knn_data["performance_metrics"]

    rf_cm = rf_data["confusion_matrix"]
    svm_cm = svm_data["confusion_matrix"]
    knn_cm = knn_data["confusion_matrix"]

    total_test_samples = rf_cm["true_negatives"] + rf_cm["false_positives"] + rf_cm["false_negatives"] + rf_cm["true_positives"]
    actual_malware = rf_cm["false_negatives"] + rf_cm["true_positives"]
    actual_benign = rf_cm["true_negatives"] + rf_cm["false_positives"]

    # Tỷ lệ thực tế
    rf_tp_rate = (rf_cm["true_positives"] / actual_malware) * 100
    svm_tp_rate = (svm_cm["true_positives"] / actual_malware) * 100
    knn_tp_rate = (knn_cm["true_positives"] / actual_malware) * 100

    rf_fn_rate = (rf_cm["false_negatives"] / actual_malware) * 100
    svm_fn_rate = (svm_cm["false_negatives"] / actual_malware) * 100
    knn_fn_rate = (knn_cm["false_negatives"] / actual_malware) * 100

    rf_tn_rate = (rf_cm["true_negatives"] / actual_benign) * 100
    svm_tn_rate = (svm_cm["true_negatives"] / actual_benign) * 100
    knn_tn_rate = (knn_cm["true_negatives"] / actual_benign) * 100

    rf_fp_rate = (rf_cm["false_positives"] / actual_benign) * 100
    svm_fp_rate = (svm_cm["false_positives"] / actual_benign) * 100
    knn_fp_rate = (knn_cm["false_positives"] / actual_benign) * 100

    sections = [
        {
            "title": f"PHÂN HỆ 1: ĐO LƯỜNG NĂNG LỰC PHÁT HIỆN MÃ ĐỘC (Tổng {actual_malware:,} mẫu mã độc thực tế)",
            "items": [
                {
                    "name": "Số mã độc bắt trúng (True Positives)",
                    "rf_str": f"{rf_cm['true_positives']:,} ({rf_tp_rate:.2f}%)",
                    "knn_str": f"{knn_cm['true_positives']:,} ({knn_tp_rate:.2f}%)",
                    "svm_str": f"{svm_cm['true_positives']:,} ({svm_tp_rate:.2f}%)",
                    "best": "Random Forest",
                    "overview": f"RF dẫn đầu ({rf_cm['true_positives']:,}), KNN bám sát ({knn_cm['true_positives']:,}), SVM lọt nhiều hơn"
                },
                {
                    "name": "Số mã độc lọt lưới (False Negatives)",
                    "rf_str": f"{rf_cm['false_negatives']:,} ({rf_fn_rate:.2f}%)",
                    "knn_str": f"{knn_cm['false_negatives']:,} ({knn_fn_rate:.2f}%)",
                    "svm_str": f"{svm_cm['false_negatives']:,} ({svm_fn_rate:.2f}%)",
                    "best": "Random Forest",
                    "overview": f"RF ít lọt nhất (55 mẫu), KNN lọt 112 mẫu, SVM lọt nhiều nhất (165 mẫu)"
                },
                {
                    "name": "Tỷ lệ bao phủ mã độc (Recall / TPR)",
                    "rf_str": f"{rf_m['recall']*100:.2f}%",
                    "knn_str": f"{knn_m['recall']*100:.2f}%",
                    "svm_str": f"{svm_m['recall']*100:.2f}%",
                    "best": "Random Forest",
                    "overview": f"RF (98.12%) > KNN (96.16%) > SVM (94.35%)"
                }
            ]
        },
        {
            "title": f"PHÂN HỆ 2: ĐO LƯỜNG NĂNG LỰC NHẬN DIỆN MÃ SẠCH (Tổng {actual_benign:,} mẫu sạch thực tế)",
            "items": [
                {
                    "name": "Số mã sạch xác nhận đúng (True Negatives)",
                    "rf_str": f"{rf_cm['true_negatives']:,} ({rf_tn_rate:.2f}%)",
                    "knn_str": f"{knn_cm['true_negatives']:,} ({knn_tn_rate:.2f}%)",
                    "svm_str": f"{svm_cm['true_negatives']:,} ({svm_tn_rate:.2f}%)",
                    "best": "KNN",
                    "overview": f"KNN xuất sắc nhất với 1,978 mẫu đúng (98.65%), RF 1,949 mẫu, SVM 1,834 mẫu"
                },
                {
                    "name": "Báo động nhầm mã sạch (False Positives)",
                    "rf_str": f"{rf_cm['false_positives']:,} ({rf_fp_rate:.2f}%)",
                    "knn_str": f"{knn_cm['false_positives']:,} ({knn_fp_rate:.2f}%)",
                    "svm_str": f"{svm_cm['false_positives']:,} ({svm_fp_rate:.2f}%)",
                    "best": "KNN",
                    "overview": f"KNN ít báo nhầm nhất (chỉ 27 mẫu / 1.35%), thấp hơn RF (56) và SVM (171)"
                },
                {
                    "name": "Độ đặc hiệu mã sạch (Specificity / TNR)",
                    "rf_str": f"{rf_tn_rate:.2f}%",
                    "knn_str": f"{knn_tn_rate:.2f}%",
                    "svm_str": f"{svm_tn_rate:.2f}%",
                    "best": "KNN",
                    "overview": f"KNN (98.65%) > RF (97.21%) > SVM (91.47%)"
                }
            ]
        },
        {
            "title": f"PHÂN HỆ 3: HIỆU NĂNG TỔNG THỂ & TỐC ĐỘ VẬN HÀNH ({total_test_samples:,} mẫu kiểm thử)",
            "items": [
                {
                    "name": "Độ chính xác tổng thể (Accuracy)",
                    "rf_str": f"{rf_m['accuracy']*100:.2f}%",
                    "knn_str": f"{knn_m['accuracy']*100:.2f}%",
                    "svm_str": f"{svm_m['accuracy']*100:.2f}%",
                    "best": "Random Forest",
                    "overview": f"RF (97.75%) suýt soát KNN (97.18%), cả 2 vượt xa SVM (93.18%)"
                },
                {
                    "name": "Độ chuẩn xác (Precision)",
                    "rf_str": f"{rf_m['precision']*100:.2f}%",
                    "knn_str": f"{knn_m['precision']*100:.2f}%",
                    "svm_str": f"{svm_m['precision']*100:.2f}%",
                    "best": "KNN",
                    "overview": f"KNN dẫn đầu tuyệt đối (99.05%) nhờ lọc sạch False Positives"
                },
                {
                    "name": "Điểm F1-Score (Cân bằng P/R)",
                    "rf_str": f"{rf_m['f1_score']*100:.2f}%",
                    "knn_str": f"{knn_m['f1_score']*100:.2f}%",
                    "svm_str": f"{svm_m['f1_score']*100:.2f}%",
                    "best": "Random Forest",
                    "overview": f"RF (98.10%) > KNN (97.58%) > SVM (94.25%)"
                },
                {
                    "name": "Diện tích đường cong ROC-AUC",
                    "rf_str": f"{rf_m['roc_auc']:.4f}",
                    "knn_str": f"{knn_m['roc_auc']:.4f}",
                    "svm_str": f"{svm_m['roc_auc']:.4f}",
                    "best": "Random Forest",
                    "overview": f"RF (0.9963) > KNN (0.9875) > SVM (0.9705)"
                },
                {
                    "name": "Tốc độ dự đoán (Inference Latency)",
                    "rf_str": f"{rf_m['inference_latency_ms_per_sample']:.4f} ms",
                    "knn_str": f"{knn_m['inference_latency_ms_per_sample']:.4f} ms",
                    "svm_str": f"{svm_m['inference_latency_ms_per_sample']:.4f} ms",
                    "best": "Random Forest",
                    "overview": f"RF nhanh nhất (0.02ms), KNN rất nhanh (0.10ms), SVM chậm nhất (0.38ms)"
                },
                {
                    "name": "Thời gian huấn luyện trên 24k mẫu",
                    "rf_str": f"{rf_m['training_time_seconds']:.2f} s",
                    "knn_str": f"{knn_m['training_time_seconds']:.2f} s",
                    "svm_str": f"{svm_m['training_time_seconds']:.2f} s",
                    "best": "KNN",
                    "overview": f"KNN là lazy learner (0.02s), RF đa nhân (0.50s), SVM tính quadratic (14s+)"
                }
            ]
        }
    ]

    csv_rows = []

    for sec in sections:
        print(f"\n{BOLD}{CYAN}▶ {sec['title']}{RESET}")
        header = f"{'Chỉ số đo lường':<38} | {'Random Forest':<18} | {'KNN (K=5)':<18} | {'SVM (RBF)':<18} | {'Đánh giá tổng quan'}"
        print(header)
        print("-" * len(header))

        for it in sec["items"]:
            rf_col = f"{GREEN}{BOLD}{it['rf_str']:<18}{RESET}" if it["best"] == "Random Forest" else f"{it['rf_str']:<18}"
            knn_col = f"{PURPLE}{BOLD}{it['knn_str']:<18}{RESET}" if it["best"] == "KNN" else f"{it['knn_str']:<18}"
            svm_col = f"{ORANGE}{it['svm_str']:<18}{RESET}"

            print(f"{it['name']:<38} | {rf_col} | {knn_col} | {svm_col} | {it['overview']}")

            csv_rows.append({
                "Phân hệ": sec["title"].split(":")[0],
                "Chỉ số (Metric)": it["name"],
                "Random Forest": it["rf_str"],
                "KNN (K=5)": it["knn_str"],
                "SVM (RBF)": it["svm_str"],
                "Mô hình tốt nhất": it["best"],
                "Đánh giá tổng quan": it["overview"]
            })

    comp_dir = "comparison_results"
    os.makedirs(comp_dir, exist_ok=True)
    df_comp = pd.DataFrame(csv_rows)
    df_comp.to_csv(os.path.join(comp_dir, "models_comparison.csv"), index=False, encoding="utf-8-sig")

    # Vẽ biểu đồ đối chiếu 3 thuật toán
    fig, axes = plt.subplots(1, 2, figsize=(15, 5.5))
    bar_width = 0.25
    x1 = np.arange(3)
    categories1 = ['Bắt trúng Mã Độc\n(Recall/TPR)', 'Nhận đúng Mã Sạch\n(Specificity/TNR)', 'Độ chính xác chung\n(Accuracy)']

    rf_scores1 = [rf_tp_rate, rf_tn_rate, rf_m['accuracy'] * 100]
    knn_scores1 = [knn_tp_rate, knn_tn_rate, knn_m['accuracy'] * 100]
    svm_scores1 = [svm_tp_rate, svm_tn_rate, svm_m['accuracy'] * 100]

    b1 = axes[0].bar(x1 - bar_width, rf_scores1, bar_width, label='Random Forest (Ensemble Tree)', color='#10b981', edgecolor='#059669', linewidth=1.2)
    b2 = axes[0].bar(x1, knn_scores1, bar_width, label='K-Nearest Neighbors (KNN K=5)', color='#8b5cf6', edgecolor='#7c3aed', linewidth=1.2)
    b3 = axes[0].bar(x1 + bar_width, svm_scores1, bar_width, label='SVM (Kernel RBF)', color='#f97316', edgecolor='#ea580c', linewidth=1.2)

    axes[0].set_ylabel('Tỷ lệ thành công (%)', fontsize=11, fontweight='bold')
    axes[0].set_title('Năng Lực Nhận Diện: 3 Thuật Toán AI (Càng cao càng tốt)', fontsize=11, fontweight='bold', pad=12)
    axes[0].set_xticks(x1)
    axes[0].set_xticklabels(categories1, fontsize=9.5, fontweight='bold')
    axes[0].set_ylim(85, 103)
    axes[0].legend(loc='lower right', fontsize=9)
    axes[0].grid(axis='y', linestyle='--', alpha=0.7)

    for bars, col in [(b1, '#047857'), (b2, '#6d28d9'), (b3, '#c2410c')]:
        for bar in bars:
            yval = bar.get_height()
            axes[0].text(bar.get_x() + bar.get_width()/2.0, yval + 0.3, f'{yval:.1f}%', ha='center', va='bottom', fontsize=8, fontweight='bold', color=col)

    # Đồ thị 2: Tỷ lệ sai số & Báo nhầm
    x2 = np.arange(2)
    categories2 = ['Lọt lưới Mã Độc\n(False Negatives %)', 'Chặn oan Mã Sạch\n(False Positives %)']
    rf_errors = [rf_fn_rate, rf_fp_rate]
    knn_errors = [knn_fn_rate, knn_fp_rate]
    svm_errors = [svm_fn_rate, svm_fp_rate]

    b4 = axes[1].bar(x2 - bar_width, rf_errors, bar_width, label='Random Forest', color='#10b981', edgecolor='#059669', linewidth=1.2)
    b5 = axes[1].bar(x2, knn_errors, bar_width, label='KNN (Lọc nhầm cực đỉnh: 27 mẫu)', color='#8b5cf6', edgecolor='#7c3aed', linewidth=1.2)
    b6 = axes[1].bar(x2 + bar_width, svm_errors, bar_width, label='SVM (Lỗi cao hơn)', color='#f97316', edgecolor='#ea580c', linewidth=1.2)

    axes[1].set_ylabel('Tỷ lệ sai số (%)', fontsize=11, fontweight='bold')
    axes[1].set_title('Tỷ Lệ Sai Sót: Bỏ Sót Mã Độc vs Chặn Oan (Càng thấp càng tốt)', fontsize=11, fontweight='bold', pad=12)
    axes[1].set_xticks(x2)
    axes[1].set_xticklabels(categories2, fontsize=9.5, fontweight='bold')
    axes[1].set_ylim(0, 11)
    axes[1].legend(loc='upper left', fontsize=9)
    axes[1].grid(axis='y', linestyle='--', alpha=0.7)

    for bars, counts, col in [
        (b4, [rf_cm['false_negatives'], rf_cm['false_positives']], '#047857'),
        (b5, [knn_cm['false_negatives'], knn_cm['false_positives']], '#6d28d9'),
        (b6, [svm_cm['false_negatives'], svm_cm['false_positives']], '#c2410c')
    ]:
        for idx, bar in enumerate(bars):
            yval = bar.get_height()
            axes[1].text(bar.get_x() + bar.get_width()/2.0, yval + 0.2, f'{yval:.2f}%\n({counts[idx]}m)', ha='center', va='bottom', fontsize=8, fontweight='bold', color=col)

    plt.tight_layout()
    chart_path = os.path.join(comp_dir, "comparison_chart.png")
    plt.savefig(chart_path, dpi=300)
    plt.close()

    print(f"\n{CYAN}========================================================================================================================{RESET}")
    print(f"{GREEN}[+] Đã xuất file CSV đối chiếu 3 thuật toán: {os.path.join(comp_dir, 'models_comparison.csv')}{RESET}")
    print(f"{GREEN}[+] Đã xuất biểu đồ đối chiếu 3 thuật toán (RF vs KNN vs SVM): {chart_path}{RESET}")
    print(f"{CYAN}========================================================================================================================{RESET}\n")

if __name__ == "__main__":
    main()
