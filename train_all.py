import os
import sys
import io
import time
import subprocess

# Thiết lập encoding UTF-8 để hiển thị tiếng Việt trên console Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

os.system("")
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
PURPLE = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

def run_script(script_path, step_name):
    print(f"\n{CYAN}{'='*80}{RESET}")
    print(f"{BOLD}{YELLOW}▶ ĐANG THỰC HIỆN: {step_name} ({script_path}){RESET}")
    print(f"{CYAN}{'='*80}{RESET}\n")

    python_executable = sys.executable
    start_time = time.time()
    
    # Thực thi script với kế thừa stdout/stderr trực tiếp
    result = subprocess.run([python_executable, script_path], check=False)
    duration = time.time() - start_time

    if result.returncode == 0:
        print(f"\n{GREEN}[✓] HOÀN TẤT: {step_name} (Thời gian thực thi: {duration:.2f}s){RESET}\n")
        return True, duration
    else:
        print(f"\n\033[91m[✗] THẤT BẠI: {step_name} (Mã lỗi: {result.returncode}){RESET}\n")
        return False, duration

def main():
    print(f"{CYAN}================================================================================{RESET}")
    print(f"{BOLD}{GREEN}     QUY TRÌNH TỰ ĐỘNG HUẤN LUYỆN TOÀN BỘ 3 THUẬT TOÁN HỌC MÁY (TRI-AI)        {RESET}")
    print(f"      1. Random Forest Classifier (Rừng cây quyết định)")
    print(f"      2. K-Nearest Neighbors Classifier (K-Lân cận khoảng cách)")
    print(f"      3. Support Vector Machine (Siêu phẳng cực đại)")
    print(f"      ➔ Tự động tổng hợp đối chiếu & xuất bảng báo cáo (compare_models.py)")
    print(f"{CYAN}================================================================================{RESET}")

    total_start = time.time()
    tasks = [
        ("RandomForest/train.py", "1. Huấn luyện Random Forest Classifier"),
        ("KNN/train.py", "2. Huấn luyện K-Nearest Neighbors (KNN)"),
        ("SVM/train.py", "3. Huấn luyện Support Vector Machine (SVM)"),
        ("compare_models.py", "4. Đối chiếu so sánh 3 thuật toán & Xuất biểu đồ")
    ]

    results = []
    for script, name in tasks:
        if not os.path.exists(script):
            print(f"\033[91m[!] Không tìm thấy tệp: {script}{RESET}")
            continue
        success, duration = run_script(script, name)
        results.append((name, success, duration))
        if not success:
            print(f"\033[91m[!] Quy trình bị gián đoạn do lỗi tại bước: {name}{RESET}")
            break

    total_duration = time.time() - total_start
    print(f"\n{CYAN}{'='*80}{RESET}")
    print(f"{BOLD}{GREEN}                   BÁO CÁO TỔNG KẾT TIẾN TRÌNH HUẤN LUYỆN                     {RESET}")
    print(f"{CYAN}{'='*80}{RESET}")
    for name, success, dur in results:
        status_str = f"{GREEN}THÀNH CÔNG{RESET}" if success else f"\033[91mTHẤT BẠI{RESET}"
        print(f" - {name:<55} : {status_str} ({dur:.2f}s)")
    print(f"{CYAN}{'-'*80}{RESET}")
    print(f"{BOLD}Tổng thời gian hoàn tất: {total_duration:.2f} giây{RESET}")
    print(f"{CYAN}{'='*80}{RESET}\n")

if __name__ == "__main__":
    main()
