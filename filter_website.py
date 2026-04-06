# Tên file đầu vào và file đầu ra (bạn có thể đổi tên cho phù hợp)
input_filename = "quic_100_percent.txt"
output_filename = "cleaned_websites.txt"

try:
    with open(input_filename, 'r') as infile, open(output_filename, 'w') as outfile:
        for line in infile:
            # Bỏ qua các dòng trống
            if not line.strip():
                continue
            
            # Cắt chuỗi tại dấu ';' và chỉ lấy phần đầu tiên (URL)
            url = line.split(';')[0].strip()
            
            # Ghi URL đã làm sạch vào file mới
            outfile.write(url + '\n')
            
    print(f"✅ Đã dọn dẹp xong! Kết quả được lưu tại file: {output_filename}")

except FileNotFoundError:
    print(f"❌ Không tìm thấy file {input_filename}. Vui lòng kiểm tra lại tên file.")