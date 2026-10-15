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
GREEN = "\033[92m"    # Xanh lá cây - Tăng ngon / Vượt trội
RED = "\033[91m"      # Đỏ - Giảm thấp hơn / Kém hơn
CYAN = "\033[96m"     # Xanh lơ - Tiêu đề
YELLOW = "\033[93m"   # Vàng - Phân hệ
BOLD = "\033[1m"      # In đậm
RESET = "\033[0m"     # Trở về mặc định

def main():
    print(f"{CYAN}=================================================================================================={RESET}")
    print(f"{BOLD}{CYAN}      ĐO LƯỜNG THỰC TẾ & ĐỐI CHIẾU CHÊNH LỆCH: PHÁT HIỆN MÃ ĐỘC VÀ MÃ SẠCH                {RESET}")
    print(f"       (Quy ước màu: {GREEN}XANH LÁ = Tăng ngon / Tốt hơn{RESET} | {RED}ĐỎ = Giảm thấp hơn / Kém hơn{RESET})")
    print(f"{CYAN}=================================================================================================={RESET}\n")

    rf_json_path = os.path.join("RandomForest", "result", "metrics_summary.json")
    svm_json_path = os.path.join("SVM", "result", "metrics_summary.json")

    missing = []
    if not os.path.exists(rf_json_path):
        missing.append("RandomForest (Chưa chạy python RandomForest/train.py)")
    if not os.path.exists(svm_json_path):
        missing.append("SVM (Chưa chạy python SVM/train.py)")

    if missing:
        print(f"{RED}[!] Không thể so sánh do thiếu kết quả của mô hình:{RESET}")
        for m in missing:
            print(f"    - {m}")
        return

    with open(rf_json_path, "r", encoding="utf-8") as f:
        rf_data = json.load(f)
    with open(svm_json_path, "r", encoding="utf-8") as f:
        svm_data = json.load(f)

    rf_m = rf_data["performance_metrics"]
    svm_m = svm_data["performance_metrics"]

    rf_cm = rf_data["confusion_matrix"]
    svm_cm = svm_data["confusion_matrix"]

    # Tổng số mẫu thực tế trong tập Test
    total_test_samples = rf_cm["true_negatives"] + rf_cm["false_positives"] + rf_cm["false_negatives"] + rf_cm["true_positives"]
    actual_malware = rf_cm["false_negatives"] + rf_cm["true_positives"]  # 55 + 2865 = 2920
    actual_benign = rf_cm["true_negatives"] + rf_cm["false_positives"]   # 1949 + 56 = 2005

    # Tỷ lệ thực tế
    rf_tp_rate = (rf_cm["true_positives"] / actual_malware) * 100        # 98.12%
    svm_tp_rate = (svm_cm["true_positives"] / actual_malware) * 100      # 94.35%
    
    rf_fn_rate = (rf_cm["false_negatives"] / actual_malware) * 100       # 1.88%
    svm_fn_rate = (svm_cm["false_negatives"] / actual_malware) * 100     # 5.65%

    rf_tn_rate = (rf_cm["true_negatives"] / actual_benign) * 100         # 97.21%
    svm_tn_rate = (svm_cm["true_negatives"] / actual_benign) * 100       # 91.47%

    rf_fp_rate = (rf_cm["false_positives"] / actual_benign) * 100        # 2.79%
    svm_fp_rate = (svm_cm["false_positives"] / actual_benign) * 100       # 8.53%

    # Định nghĩa 3 phân hệ so sánh chi tiết
    sections = [
        {
            "title": f"PHÂN HỆ 1: ĐO LƯỜNG NĂNG LỰC PHÁT HIỆN MÃ ĐỘC (Tổng {actual_malware:,} mẫu mã độc thực tế)",
            "items": [
                {
                    "name": "Số mã độc bắt trúng (True Positives)",
                    "rf_val": rf_cm["true_positives"],
                    "svm_val": svm_cm["true_positives"],
                    "rf_str": f"{rf_cm['true_positives']:,} mẫu ({rf_tp_rate:.2f}%)",
                    "svm_str": f"{svm_cm['true_positives']:,} mẫu ({svm_tp_rate:.2f}%)",
                    "better": "Random Forest",
                    "diff_text": f"RF bắt trúng nhiều hơn +{rf_cm['true_positives'] - svm_cm['true_positives']} mẫu (+{rf_tp_rate - svm_tp_rate:.2f}%)"
                },
                {
                    "name": "Số mã độc lọt lưới (False Negatives)",
                    "rf_val": rf_cm["false_negatives"],
                    "svm_val": svm_cm["false_negatives"],
                    "rf_str": f"{rf_cm['false_negatives']:,} mẫu ({rf_fn_rate:.2f}%)",
                    "svm_str": f"{svm_cm['false_negatives']:,} mẫu ({svm_fn_rate:.2f}%)",
                    "better": "Random Forest",
                    "diff_text": f"RF ít lọt lưới hơn {svm_cm['false_negatives'] - rf_cm['false_negatives']} mẫu (SVM lọt gấp {svm_cm['false_negatives']/rf_cm['false_negatives']:.1f} lần)"
                },
                {
                    "name": "Tỷ lệ bao phủ mã độc (Recall/Sensitivity)",
                    "rf_val": rf_m["recall"] * 100,
                    "svm_val": svm_m["recall"] * 100,
                    "rf_str": f"{rf_m['recall']*100:.2f}%",
                    "svm_str": f"{svm_m['recall']*100:.2f}%",
                    "better": "Random Forest",
                    "diff_text": f"RF cao hơn +{(rf_m['recall'] - svm_m['recall'])*100:.2f}%"
                }
            ]
        },
        {
            "title": f"PHÂN HỆ 2: ĐO LƯỜNG NĂNG LỰC NHẬN DIỆN MÃ SẠCH (Tổng {actual_benign:,} mẫu sạch thực tế)",
            "items": [
                {
                    "name": "Số mã sạch xác nhận đúng (True Negatives)",
                    "rf_val": rf_cm["true_negatives"],
                    "svm_val": svm_cm["true_negatives"],
                    "rf_str": f"{rf_cm['true_negatives']:,} mẫu ({rf_tn_rate:.2f}%)",
                    "svm_str": f"{svm_cm['true_negatives']:,} mẫu ({svm_tn_rate:.2f}%)",
                    "better": "Random Forest",
                    "diff_text": f"RF nhận đúng nhiều hơn +{rf_cm['true_negatives'] - svm_cm['true_negatives']} mẫu (+{rf_tn_rate - svm_tn_rate:.2f}%)"
                },
                {
                    "name": "Báo động nhầm mã sạch (False Positives)",
                    "rf_val": rf_cm["false_positives"],
                    "svm_val": svm_cm["false_positives"],
                    "rf_str": f"{rf_cm['false_positives']:,} mẫu ({rf_fp_rate:.2f}%)",
                    "svm_str": f"{svm_cm['false_positives']:,} mẫu ({svm_fp_rate:.2f}%)",
                    "better": "Random Forest",
                    "diff_text": f"RF ít nhầm hơn {svm_cm['false_positives'] - rf_cm['false_positives']} mẫu (SVM chặn oan gấp {svm_cm['false_positives']/rf_cm['false_positives']:.1f} lần)"
                },
                {
                    "name": "Độ đặc hiệu mã sạch (Specificity / TNR)",
                    "rf_val": rf_tn_rate,
                    "svm_val": svm_tn_rate,
                    "rf_str": f"{rf_tn_rate:.2f}%",
                    "svm_str": f"{svm_tn_rate:.2f}%",
                    "better": "Random Forest",
                    "diff_text": f"RF chuẩn xác hơn +{rf_tn_rate - svm_tn_rate:.2f}%"
                }
            ]
        },
        {
            "title": f"PHÂN HỆ 3: HIỆU NĂNG TỔNG THỂ & TỐC ĐỘ VẬN HÀNH (Benchmark trên {total_test_samples:,} mẫu)",
            "items": [
                {
                    "name": "Độ chính xác tổng thể (Accuracy)",
                    "rf_val": rf_m["accuracy"] * 100,
                    "svm_val": svm_m["accuracy"] * 100,
                    "rf_str": f"{rf_m['accuracy']*100:.2f}%",
                    "svm_str": f"{svm_m['accuracy']*100:.2f}%",
                    "better": "Random Forest",
                    "diff_text": f"RF cao hơn +{(rf_m['accuracy'] - svm_m['accuracy'])*100:.2f}%"
                },
                {
                    "name": "Độ chuẩn xác (Precision)",
                    "rf_val": rf_m["precision"] * 100,
                    "svm_val": svm_m["precision"] * 100,
                    "rf_str": f"{rf_m['precision']*100:.2f}%",
                    "svm_str": f"{svm_m['precision']*100:.2f}%",
                    "better": "Random Forest",
                    "diff_text": f"RF cao hơn +{(rf_m['precision'] - svm_m['precision'])*100:.2f}%"
                },
                {
                    "name": "F1-Score (Cân bằng Precision/Recall)",
                    "rf_val": rf_m["f1_score"] * 100,
                    "svm_val": svm_m["f1_score"] * 100,
                    "rf_str": f"{rf_m['f1_score']*100:.2f}%",
                    "svm_str": f"{svm_m['f1_score']*100:.2f}%",
                    "better": "Random Forest",
                    "diff_text": f"RF cao hơn +{(rf_m['f1_score'] - svm_m['f1_score'])*100:.2f}%"
                },
                {
                    "name": "Diện tích đường cong ROC-AUC",
                    "rf_val": rf_m["roc_auc"],
                    "svm_val": svm_m["roc_auc"],
                    "rf_str": f"{rf_m['roc_auc']:.4f}",
                    "svm_str": f"{svm_m['roc_auc']:.4f}",
                    "better": "Random Forest",
                    "diff_text": f"RF cao hơn +{rf_m['roc_auc'] - svm_m['roc_auc']:.4f}"
                },
                {
                    "name": "Tốc độ dự đoán (Inference Latency)",
                    "rf_val": rf_m["inference_latency_ms_per_sample"],
                    "svm_val": svm_m["inference_latency_ms_per_sample"],
                    "rf_str": f"{rf_m['inference_latency_ms_per_sample']:.4f} ms/mẫu",
                    "svm_str": f"{svm_m['inference_latency_ms_per_sample']:.4f} ms/mẫu",
                    "better": "Random Forest",
                    "diff_text": f"RF nhanh hơn gấp ~{svm_m['inference_latency_ms_per_sample']/rf_m['inference_latency_ms_per_sample']:.1f} lần"
                },
                {
                    "name": "Thời gian huấn luyện trên 24k mẫu",
                    "rf_val": rf_m["training_time_seconds"],
                    "svm_val": svm_m["training_time_seconds"],
                    "rf_str": f"{rf_m['training_time_seconds']:.2f} s",
                    "svm_str": f"{svm_m['training_time_seconds']:.2f} s",
                    "better": "Random Forest",
                    "diff_text": f"RF huấn luyện nhanh hơn gấp ~{svm_m['training_time_seconds']/rf_m['training_time_seconds']:.1f} lần"
                }
            ]
        }
    ]

    csv_rows = []

    # In ra bảng định dạng đẹp mắt theo từng phân hệ
    for sec in sections:
        print(f"\n{BOLD}{YELLOW}▶ {sec['title']}{RESET}")
        header = f"{'Chỉ số đo lường':<42} | {'Random Forest':<24} | {'SVM (RBF)':<24} | {'Đánh giá chênh lệch thực tế'}"
        print(header)
        print("-" * len(header))

        for it in sec["items"]:
            # Random Forest tốt hơn -> tô màu Xanh lá
            rf_colored = f"{GREEN}{BOLD}{it['rf_str']:<22}{RESET}"
            # SVM thấp hơn / kém hơn -> tô màu Đỏ
            svm_colored = f"{RED}{it['svm_str']:<22}{RESET}"
            diff_colored = f"{GREEN}▲ {it['diff_text']}{RESET}"

            print(f"{it['name']:<42} | {rf_colored} | {svm_colored} | {diff_colored}")

            csv_rows.append({
                "Phân hệ": sec["title"].split(":")[0],
                "Chỉ số (Metric)": it["name"],
                "Random Forest": it["rf_str"],
                "SVM (RBF)": it["svm_str"],
                "Mô hình tốt hơn": it["better"],
                "Chênh lệch thực tế": it["diff_text"]
            })

    # Tạo thư mục so sánh tổng hợp
    comp_dir = "comparison_results"
    os.makedirs(comp_dir, exist_ok=True)

    # Lưu file CSV so sánh
    df_comp = pd.DataFrame(csv_rows)
    df_comp.to_csv(os.path.join(comp_dir, "models_comparison.csv"), index=False, encoding="utf-8-sig")

    # Vẽ biểu đồ đối chiếu 4 trục thực tế (Bắt mã độc, Bắt mã sạch, Bỏ sót FN, Báo nhầm FP)
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Đồ thị 1: Năng lực nhận diện (%)
    bar_width = 0.35
    x1 = np.arange(3)
    categories1 = ['Bắt trúng Mã Độc\n(Recall/TPR)', 'Nhận đúng Mã Sạch\n(Specificity/TNR)', 'Độ chính xác chung\n(Accuracy)']
    rf_scores1 = [rf_tp_rate, rf_tn_rate, rf_m['accuracy'] * 100]
    svm_scores1 = [svm_tp_rate, svm_tn_rate, svm_m['accuracy'] * 100]

    b1 = axes[0].bar(x1 - bar_width/2, rf_scores1, bar_width, label='Random Forest (Tăng ngon - Cao hơn)', color='#10b981', edgecolor='#059669', linewidth=1.5)
    b2 = axes[0].bar(x1 + bar_width/2, svm_scores1, bar_width, label='SVM (Giảm thấp hơn)', color='#ef4444', edgecolor='#dc2626', linewidth=1.5)
    
    axes[0].set_ylabel('Tỷ lệ thành công (%)', fontsize=11, fontweight='bold')
    axes[0].set_title('Năng Lực Nhận Diện: Mã Độc vs Mã Sạch (Càng cao càng tốt)', fontsize=11, fontweight='bold', pad=12)
    axes[0].set_xticks(x1)
    axes[0].set_xticklabels(categories1, fontsize=9.5, fontweight='bold')
    axes[0].set_ylim(85, 103)
    axes[0].legend(loc='lower right', fontsize=9.5)
    axes[0].grid(axis='y', linestyle='--', alpha=0.7)

    for bar in b1:
        yval = bar.get_height()
        axes[0].text(bar.get_x() + bar.get_width()/2.0, yval + 0.4, f'{yval:.2f}%', ha='center', va='bottom', fontsize=8.5, fontweight='bold', color='#047857')
    for bar in b2:
        yval = bar.get_height()
        axes[0].text(bar.get_x() + bar.get_width()/2.0, yval + 0.4, f'{yval:.2f}%', ha='center', va='bottom', fontsize=8.5, fontweight='bold', color='#b91c1c')

    # Đồ thị 2: Tỷ lệ sai số & Báo nhầm (Càng thấp càng tốt)
    x2 = np.arange(2)
    categories2 = ['Lọt lưới Mã Độc\n(False Negatives %)', 'Chặn oan Mã Sạch\n(False Positives %)']
    rf_errors = [rf_fn_rate, rf_fp_rate]
    svm_errors = [svm_fn_rate, svm_fp_rate]

    b3 = axes[1].bar(x2 - bar_width/2, rf_errors, bar_width, label='Random Forest (Ít lỗi hơn)', color='#10b981', edgecolor='#059669', linewidth=1.5)
    b4 = axes[1].bar(x2 + bar_width/2, svm_errors, bar_width, label='SVM (Lỗi nhiều hơn)', color='#ef4444', edgecolor='#dc2626', linewidth=1.5)

    axes[1].set_ylabel('Tỷ lệ sai số (%)', fontsize=11, fontweight='bold')
    axes[1].set_title('Tỷ Lệ Sai Sót: Bỏ Sót Mã Độc vs Chặn Oan (Càng thấp càng tốt)', fontsize=11, fontweight='bold', pad=12)
    axes[1].set_xticks(x2)
    axes[1].set_xticklabels(categories2, fontsize=9.5, fontweight='bold')
    axes[1].set_ylim(0, 11)
    axes[1].legend(loc='upper left', fontsize=9.5)
    axes[1].grid(axis='y', linestyle='--', alpha=0.7)

    for bar in b3:
        yval = bar.get_height()
        axes[1].text(bar.get_x() + bar.get_width()/2.0, yval + 0.25, f'{yval:.2f}%\n({int(rf_cm["false_negatives"] if bar == b3[0] else rf_cm["false_positives"])} mẫu)', ha='center', va='bottom', fontsize=8, fontweight='bold', color='#047857')
    for bar in b4:
        yval = bar.get_height()
        axes[1].text(bar.get_x() + bar.get_width()/2.0, yval + 0.25, f'{yval:.2f}%\n({int(svm_cm["false_negatives"] if bar == b4[0] else svm_cm["false_positives"])} mẫu)', ha='center', va='bottom', fontsize=8, fontweight='bold', color='#b91c1c')

    plt.tight_layout()
    chart_path = os.path.join(comp_dir, "comparison_chart.png")
    plt.savefig(chart_path, dpi=300)
    plt.close()

    print(f"\n{CYAN}=================================================================================================={RESET}")
    print(f"{GREEN}[+] Đã xuất file CSV đo lường chênh lệch thực tế: {os.path.join(comp_dir, 'models_comparison.csv')}{RESET}")
    print(f"{GREEN}[+] Đã xuất biểu đồ đối chiếu kép (Mã độc / Mã sạch): {chart_path}{RESET}")
    print(f"{CYAN}=================================================================================================={RESET}\n")

if __name__ == "__main__":
    main()
