import os

# 🔧 Chỉnh sửa đường dẫn tại đây
PARENT_FOLDER = "/duong/dan/toi/folder_cha"
OUTPUT_FILE = "report.txt"


def count_lines_in_csv(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return sum(1 for _ in f)
    except Exception as e:
        print(f"Lỗi khi đọc file {file_path}: {e}")
        return 0


def process_parent_folder(parent_folder, output_file):
    results = []

    for subfolder in os.listdir(parent_folder):
        subfolder_path = os.path.join(parent_folder, subfolder)

        if os.path.isdir(subfolder_path):
            csv_files = [f for f in os.listdir(subfolder_path) if f.endswith('.csv')]

            if not csv_files:
                continue

            line_counts = []

            for csv_file in csv_files:
                file_path = os.path.join(subfolder_path, csv_file)
                lines = count_lines_in_csv(file_path)
                line_counts.append(lines)

            file_count = len(line_counts)
            avg_lines = sum(line_counts) / file_count if file_count > 0 else 0
            min_lines = min(line_counts)
            max_lines = max(line_counts)

            results.append((subfolder, file_count, avg_lines, min_lines, max_lines))

    # Ghi file kết quả
    with open(output_file, 'w', encoding='utf-8') as f:
        for subfolder, file_count, avg_lines, min_lines, max_lines in results:
            f.write(f"Folder: {subfolder}\n")
            f.write(f"  So file CSV: {file_count}\n")
            f.write(f"  Trung binh so dong: {avg_lines:.2f}\n")
            f.write(f"  It nhat: {min_lines}\n")
            f.write(f"  Nhieu nhat: {max_lines}\n\n")

    print(f"Đã ghi kết quả vào {output_file}")


if __name__ == "__main__":
    process_parent_folder(PARENT_FOLDER, OUTPUT_FILE)