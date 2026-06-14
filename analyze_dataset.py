import os
import re

def analyze_cwe_distances(cwe: str, dataset_dir: str):
    if cwe == "79":
        sources = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES']
        sinks   = ['echo', 'print', 'printf', 'die(', 'exit(', 'header(']
    else:
        sources = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER']
        sinks   = ['query(', 'execute(', 'mysqli_query', 'mysql_query', 'pg_query', 'sqlite_query', 'prepare(']

    path = dataset_dir.replace("{cwe}", cwe)
    if not os.path.exists(path):
        print(f"[Lỗi] Không tìm thấy thư mục: {path}")
        return

    distances = []
    total_vulnerable_files = 0
    analyzed_files = 0

    for filename in os.listdir(path):
        if filename.startswith("bad_"):  # Chỉ phân tích file có lỗi thực tế
            total_vulnerable_files += 1
            filepath = os.path.join(path, filename)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                
                source_lines = []
                sink_lines = []
                
                for idx, line in enumerate(lines):
                    if any(src in line for src in sources):
                        source_lines.append(idx)
                    if any(snk in line for snk in sinks):
                        sink_lines.append(idx)
                
                if source_lines and sink_lines:
                    # Tính khoảng cách nhỏ nhất giữa một cặp source và sink trong cùng một file
                    min_dist = min(abs(src - snk) for src in source_lines for snk in sink_lines)
                    distances.append(min_dist)
                    analyzed_files += 1
            except Exception as e:
                pass

    if not distances:
        print(f"CWE-{cwe}: Không tìm thấy cặp Source/Sink nào để đo khoảng cách.")
        return

    distances.sort()
    avg_dist = sum(distances) / len(distances)
    median_dist = distances[len(distances) // 2]
    p90_dist = distances[int(len(distances) * 0.90)]
    max_dist = max(distances)

    print(f"\n=== THỐNG KÊ KHOẢNG CÁCH SOURCE - SINK (CWE-{cwe}) ===")
    print(f"Tổng số file lỗi (bad_*): {total_vulnerable_files}")
    print(f"Số file nhận diện được luồng Source -> Sink: {analyzed_files}")
    print(f"Khoảng cách dòng trung bình (Average Distance): {avg_dist:.2f} dòng")
    print(f"Khoảng cách dòng trung vị (Median Distance)     : {median_dist} dòng")
    print(f"Khoảng cách ở phân vị 90% (90th Percentile)     : {p90_dist} dòng")
    print(f"Khoảng cách lớn nhất (Max Distance)             : {max_dist} dòng")
    print(f"--------------------------------------------------")
    print(f"Khuyến nghị kích thước Slicing window: lấy +/- {int(p90_dist/2) + 1} hoặc {int(median_dist/2) + 1} dòng xung quanh.")

# Chạy thử nghiệm cho cả 2 CWE
if __name__ == "__main__":
    base_dir = r"data/dataset/dataset_final_sorted/CWE-{cwe}/php"
    # Sửa lại đường dẫn nếu thư mục của bạn nằm ở vị trí khác
    if not os.path.exists("data"):
        base_dir = r"D:\RealVul-emnlp24\data\dataset\dataset_final_sorted\CWE-{cwe}\php"
        
    analyze_cwe_distances("79", base_dir)
    analyze_cwe_distances("89", base_dir)