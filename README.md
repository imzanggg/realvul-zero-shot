# RealVul Zero-Shot Evaluation

Đồ án môn học: **Lập trình An toàn và Khai thác Lỗ hổng Phần mềm**

Tái hiện và mở rộng pipeline RealVul (EMNLP 2024) theo hướng 
zero-shot prompting với 5 model local chạy qua Ollama.

## Mô tả

- **Bài báo gốc:** RealVul (EMNLP 2024) — Di Cao, Yong Liao, Xiuwei Shang
- **Hướng mở rộng:** Zero-shot prompting, không fine-tune
- **Quy mô:** 4 prompt strategies × 5 models × 2 CWE = 40 thí nghiệm
- **CWE:** CWE-79 (XSS) và CWE-89 (SQL Injection)

## Models sử dụng (qua Ollama)

- qwen2.5-coder:7b
- codellama:7b
- deepseek-coder:6.7b
- llama3.2:3b
- phi3.5:3.8b

## Prompt Strategies

1. Standard (Zero-shot)
2. CoT (Chain-of-Thought)
3. Sliced Standard
4. Sliced CoT

## Cài đặt

```bash
pip install -r requirements.txt
```

Cài Ollama: https://ollama.com
Pull model:
```bash
ollama pull codellama:7b
```

## Chạy thực nghiệm

```bash
# Chạy 1 thí nghiệm đơn lẻ
python ollama_eval.py --cwe 79 --model codellama:7b --mode standard

# Chạy toàn bộ 40 thí nghiệm
run_all.bat
```

## Chạy với Groq API (tùy chọn)

Tạo file `.env`:
GROQ_API_KEY=your_api_key_here
Lấy API key tại: https://console.groq.com

```bash
python groq_eval.py --cwe 79 --mode standard
```

## Kết quả

Kết quả được lưu trong thư mục `results/` (40 file JSON) 
và `results_groq_*.json` (8 file JSON từ Groq API).

Model tốt nhất: **codellama:7b**
- CWE-79: F1 = 0.6757 (Sliced strategy)
- CWE-89: F1 = 0.6711 (Standard strategy)
