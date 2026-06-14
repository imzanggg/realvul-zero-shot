"""
ollama_eval.py - Tích hợp Ollama (offline LLM) vào pipeline RealVul
Đặt file này vào thư mục gốc: D:\\RealVul-emnlp24\\

Cách chạy:
    python ollama_eval.py --cwe 79 --model qwen2.5-coder:7b

Yêu cầu:
    - Ollama đã cài và đang chạy (ollama serve)
    - Model đã tải: ollama pull qwen2.5-coder:7b
    - pip install requests scikit-learn tqdm
"""
import os
import argparse
import json
import time
import random
import requests
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score,
    recall_score, classification_report, confusion_matrix
)
from tqdm import tqdm

# ============================================================
# CẤU HÌNH
# ============================================================
OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "qwen2.5-coder:7b"

LABEL_VULNERABLE = 1
LABEL_SAFE = 0

# ============================================================
# PROMPT TEMPLATES
# ============================================================

def build_prompt_standard(code_snippet: str, cwe: str) -> str:
    """Prompt chuẩn (Zero-shot) - tái hiện bài báo"""
    vuln_type = "Cross-Site Scripting (XSS)" if cwe == "79" else "SQL Injection"
    cwe_label = f"CWE-{cwe}"

    return f"""Analyze the following PHP code snippet for {vuln_type} ({cwe_label}) vulnerabilities.

PHP Code:
```php
{code_snippet}
```

Instructions:
- Carefully examine the code for {vuln_type} vulnerabilities
- Consider user input sources, data flows, and output contexts
- Only flag code that is CLEARLY and DEFINITIVELY vulnerable
- When in doubt, answer SAFE
- Answer ONLY with: VULNERABLE or SAFE
- Do not explain, just output one word

Answer:"""


def build_prompt_cot(code_snippet: str, cwe: str) -> str:
    """
    Chain-of-Thought prompt nâng cấp — Ép mô hình phân tích theo dạng Cổng Kiểm Tra nghiêm ngặt.
    Giúp cải thiện độ chính xác cho các dòng model nhỏ (7B) bằng cách hạn chế bỏ bước.
    """
    if cwe == "79":
        vuln_type = "Cross-Site Scripting (XSS)"
        cwe_label = "CWE-79"
        sources  = "$_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER"
        sinks    = "echo, print, printf, header(), die(), exit()"
        sanitize = "htmlspecialchars(), htmlentities(), strip_tags(), intval(), floatval()"
    else:
        vuln_type = "SQL Injection"
        cwe_label = "CWE-89"
        sources  = "$_GET, $_POST, $_REQUEST, $_COOKIE"
        sinks    = "mysql_query(), mysqli_query(), query(), execute(), prepare()"
        sanitize = "mysqli_real_escape_string(), intval(), floatval(), prepared statements with bound params"

    return f"""You are a static code analysis tool. Analyze the following PHP code strictly for {vuln_type} ({cwe_label}) vulnerabilities.

PHP Code:
```php
{code_snippet}
```

Perform the security analysis by executing the following 4 verification gates in order. You must write down your analysis for each gate.
GATE 1 - SOURCE SEARCH:
Scan the code for any user input sources ({sources}).
List the exact variable names that receive these inputs.
If no source variables are found, stop here, write "GATE 1: FAILED" and output the final verdict: SAFE.
GATE 2 - DATA FLOW TRACING:
Trace the data flow of each identified source variable line-by-line.
Write down every assignment or concatenation involving these variables (e.g., $var_a = $source -> $var_b = $var_a . "text").
If the flow is broken or does not reach any output/sink, write "GATE 2: FAILED" and output the final verdict: SAFE.
GATE 3 - SANITIZATION VERIFICATION:
Check if any secure sanitization, validation, or type-casting functions ({sanitize}) are applied to the tracked variables BEFORE they reach any sink.
Note down: "SANITIZED" (and specify the function used) or "UNSANITIZED" for each flow.
GATE 4 - SINK MATCHING:
Identify all execution or output sinks ({sinks}) in the code.
Check if an UNSANITIZED variable from GATE 3 is passed directly into any of these sinks.
If an unsanitized flow enters a sink, write "GATE 4: COMPROMISED".
VERDICT RULE:
If and only if GATE 4 is "COMPROMISED", the verdict is VULNERABLE.
Otherwise, the verdict is SAFE.
Provide your step-by-step analysis for each GATE, then output the final line exactly in this format:
VERDICT: [VULNERABLE or SAFE]"""


def build_prompt_sliced(code_snippet: str, cwe: str, use_cot: bool = False) -> str:
    """Prompt cho code đã được slice"""
    if cwe == "79":
        vuln_type = "Cross-Site Scripting (XSS)"
        cwe_label = "CWE-79"
        sources  = "$_GET, $_POST, $_REQUEST, $_COOKIE"
        sinks    = "echo, print, printf, header()"
        sanitize = "htmlspecialchars(), htmlentities(), strip_tags()"
    else:
        vuln_type = "SQL Injection"
        cwe_label = "CWE-89"
        sources  = "$_GET, $_POST, $_REQUEST, $_COOKIE"
        sinks    = "mysql_query(), mysqli_query(), query(), execute()"
        sanitize = "mysqli_real_escape_string(), intval(), prepared statements"

    if use_cot:
        return f"""You are a PHP security analyst. This is a program SLICE — only source/sink-relevant lines are shown.
Analyze for {vuln_type} ({cwe_label}).

PHP slice:
```php
{code_snippet}
```

STEP 1 - SOURCE: Which variables carry user input ({sources})?
STEP 2 - FLOW: How does each source variable reach the output? (trace assignments)
STEP 3 - SANITIZATION: Is {sanitize} applied before the sink?
STEP 4 - SINK: Does {sinks} receive unsanitized user data?
STEP 5 - VERDICT: Source → no sanitization → sink = VULNERABLE, else SAFE.

VERDICT: [VULNERABLE or SAFE]"""
    else:
        return f"""Analyze this PHP code slice for {vuln_type} ({cwe_label}) vulnerabilities.
This is a program slice containing only the relevant source/sink lines.

PHP code slice:
```php
{code_snippet}
```

Instructions:
- Only flag code that is CLEARLY and DEFINITIVELY vulnerable
- When in doubt, answer SAFE
- Answer ONLY with: VULNERABLE or SAFE
- Do not explain, just output one word

Answer:"""


# ============================================================
# PROGRAM SLICING
# ============================================================

def simple_slice(code: str, cwe: str) -> str:
    """
    Trích xuất các dòng liên quan đến source/sink.
    Tái hiện bước Program Slicing trong bài báo RealVul.
    """
    if cwe == "79":
        sources = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE',
                   '$_SERVER', '$_FILES', '$HTTP_GET_VARS']
        sinks   = ['echo', 'print', 'printf', 'die(', 'exit(',
                   'header(', 'document.write', 'innerHTML']
    else:  # CWE-89
        sources = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE',
                   '$_SERVER', '$_FILES']
        sinks   = ['query(', 'execute(', 'mysqli_query', 'mysql_query',
                   'pg_query', 'sqlite_query', 'prepare(']

    lines = code.split('\n')
    selected = set()

    for i, line in enumerate(lines):
        if any(s in line for s in sources + sinks):
            # Lấy ±5 dòng xung quanh mỗi dòng có source/sink
            for j in range(max(0, i - 5), min(len(lines), i + 6)):
                selected.add(j)

    if not selected:
        return code  # fallback: trả về nguyên bản

    sliced = [lines[i] for i in sorted(selected)]

    if len(sliced) < 3:
        return code  # slice quá ngắn → trả về nguyên bản

    return '\n'.join(sliced)

# ============================================================
# NORMALIZATION
# ============================================================

import re

def normalize_code(code: str) -> str:
    """
    Chuẩn hóa tên biến/hàm về dạng trừu tượng.
    Tái hiện kỹ thuật Normalization trong bài báo RealVul.
    - Biến người dùng định nghĩa → $var1, $var2, ...
    - Hàm người dùng định nghĩa → func1(), func2(), ...
    - Giữ nguyên: $_GET, $_POST, $_COOKIE, $_REQUEST, $_SERVER,
                  các hàm built-in PHP (echo, print, htmlspecialchars,
                  mysql_query, mysqli_query, ...)
    """

    # Danh sách từ khóa PHP giữ nguyên (không normalize)
    PHP_BUILTINS = {
        # Superglobals (sources)
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE',
        '$_SERVER', '$_FILES', '$_SESSION', '$_ENV',
        # Hàm sanitization
        'htmlspecialchars', 'htmlentities', 'strip_tags',
        'addslashes', 'mysql_real_escape_string',
        'mysqli_real_escape_string', 'intval', 'floatval',
        'filter_input', 'filter_var', 'preg_replace',
        # Hàm sink XSS
        'echo', 'print', 'printf', 'die', 'exit', 'header',
        # Hàm sink SQLi
        'mysql_query', 'mysqli_query', 'pg_query',
        'sqlite_query', 'query', 'execute', 'prepare',
        # Hàm kết nối DB
        'mysqli_connect', 'mysql_connect', 'PDO',
        # Từ khóa PHP
        'if', 'else', 'elseif', 'while', 'for', 'foreach',
        'return', 'function', 'class', 'new', 'true', 'false',
        'null', 'isset', 'empty', 'array', 'list', 'count',
        'strlen', 'substr', 'str_replace', 'trim', 'explode',
        'implode', 'in_array', 'include', 'require',
        'include_once', 'require_once',
    }

    var_map  = {}   # $userName → $var1
    func_map = {}   # myFunc   → func1
    var_counter  = [1]
    func_counter = [1]

    def replace_variable(match):
        var_name = match.group(0)
        # Giữ nguyên superglobals và biến đặc biệt
        if var_name in PHP_BUILTINS:
            return var_name
        if var_name.startswith('$_'):
            return var_name
        if var_name not in var_map:
            var_map[var_name] = f'$var{var_counter[0]}'
            var_counter[0] += 1
        return var_map[var_name]

    def replace_function(match):
        func_name = match.group(1)
        # Giữ nguyên built-in functions
        if func_name.lower() in {b.lower() for b in PHP_BUILTINS}:
            return match.group(0)
        if func_name not in func_map:
            func_map[func_name] = f'func{func_counter[0]}'
            func_counter[0] += 1
        return match.group(0).replace(func_name, func_map[func_name])

    # Xử lý từng dòng
    lines = code.split('\n')
    normalized_lines = []

    for line in lines:
        # Bỏ qua comment
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('#'):
            normalized_lines.append(line)
            continue
        if stripped.startswith('*') or stripped.startswith('/*'):
            normalized_lines.append(line)
            continue

        # Normalize tên hàm (function myFunc → function func1)
        line = re.sub(
            r'\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            replace_function,
            line
        )

        # Normalize biến ($userName → $var1)
        line = re.sub(r'\$[a-zA-Z_][a-zA-Z0-9_]*', replace_variable, line)

        normalized_lines.append(line)

    return '\n'.join(normalized_lines)


def normalize_stats(original: str, normalized: str) -> dict:
    """Thống kê số biến/hàm đã được normalize"""
    orig_vars  = set(re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', original))
    norm_vars  = set(re.findall(r'\$var\d+', normalized))
    return {
        "original_var_count"   : len(orig_vars),
        "normalized_var_count" : len(norm_vars),
    }


def slice_stats(original: str, sliced: str) -> dict:
    orig_lines   = len(original.split('\n'))
    sliced_lines = len(sliced.split('\n'))
    ratio = sliced_lines / orig_lines if orig_lines > 0 else 1.0
    return {
        "original_lines": orig_lines,
        "sliced_lines": sliced_lines,
        "compression_ratio": round(ratio, 3)
    }


# ============================================================
# GỌI OLLAMA API
# ============================================================

def call_ollama(prompt: str, model: str, timeout: int = 120) -> str:
    """Gửi prompt đến Ollama và nhận response"""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": 600 if "STEP 1" in prompt else 150,
        }
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=timeout)
        response.raise_for_status()
        result = response.json()
        return result.get("response", "").strip()
    except requests.exceptions.ConnectionError:
        print("\n[LỖI] Không kết nối được Ollama! Hãy chạy: ollama serve")
        raise
    except requests.exceptions.Timeout:
        print(f"\n[TIMEOUT] Model phản hồi quá chậm (>{timeout}s)")
        return "TIMEOUT"
    except Exception as e:
        print(f"\n[LỖI] {e}")
        return "ERROR"


def parse_prediction(raw_output: str) -> int:
    # Ưu tiên dòng VERDICT: (giữ nguyên, đây là đúng)
    for line in raw_output.upper().splitlines():
        line = line.strip()
        if line.startswith("VERDICT:"):
            verdict = line.replace("VERDICT:", "").strip()
            if "VULNERABLE" in verdict:
                return LABEL_VULNERABLE
            if "SAFE" in verdict:
                return LABEL_SAFE

    # Fallback: chỉ tìm ở 3 dòng CUỐI (phần kết luận)
    last_lines = "\n".join(raw_output.upper().splitlines()[-3:])
    if "VULNERABLE" in last_lines:
        return LABEL_VULNERABLE
    if "SAFE" in last_lines:
        return LABEL_SAFE

    # Fallback cuối: toàn text — BỎ "SANITIZED" khỏi safe_keywords
    text = raw_output.upper()
    vuln_keywords = ["YES", "VULN", "INSECURE", "DANGER"]
    safe_keywords = ["NO", "CLEAN", "SECURE", "PROTECTED"]  # bỏ SANITIZED
    for kw in vuln_keywords:
        if kw in text:
            return LABEL_VULNERABLE
    for kw in safe_keywords:
        if kw in text:
            return LABEL_SAFE

    return LABEL_SAFE


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset_from_dir(dataset_dir: str, cwe: str,
                          max_samples: int = None,
                          max_file_kb: int = 8) -> list:
    samples = []

    if not os.path.exists(dataset_dir):
        raise FileNotFoundError(f"Không tìm thấy thư mục: {dataset_dir}")

    all_files = [f for f in os.listdir(dataset_dir)
                 if os.path.isfile(os.path.join(dataset_dir, f))]
    print(f"[INFO] Tổng số file: {len(all_files)}")

    for filename in all_files:
        filepath = os.path.join(dataset_dir, filename)

        if filename.startswith("bad_"):
            label = LABEL_VULNERABLE   # bad_*.php = có lỗ hổng
        elif filename.startswith(("good_", "fix_", "safe_")):
            label = LABEL_SAFE         # good_*.php = an toàn
        else:
            continue

        size = os.path.getsize(filepath)
        if size <= 14:                # Bỏ file quá nhỏ
            continue
        if size > max_file_kb * 1024:
            continue                  # Bỏ file > 8KB

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read().strip()
            if code:
                samples.append({"code": code, "label": label, "filename": filename})
        except Exception as e:
            print(f"[WARN] Không đọc được {filename}: {e}")

    print(f"[INFO] Sau lọc còn: {len(samples)} samples")

    if max_samples:
        vuln = [s for s in samples if s["label"] == LABEL_VULNERABLE]
        safe = [s for s in samples if s["label"] == LABEL_SAFE]

        random.seed(42)
        random.shuffle(vuln)
        random.shuffle(safe)

        half       = max_samples // 2
        vuln_count = min(half, len(vuln))
        safe_count = min(half, len(safe))
        samples    = vuln[:vuln_count] + safe[:safe_count]

        if len(vuln) != len(safe):
            print(f"[WARN] Dataset không balanced: {len(vuln)} vuln vs {len(safe)} safe")
        print(f"[INFO] Lấy: {vuln_count} vuln + {safe_count} safe = {len(samples)} samples")
        random.shuffle(samples)

    print(f"[INFO] Đã load {len(samples)} samples "
          f"({sum(1 for s in samples if s['label']==1)} vulnerable, "
          f"{sum(1 for s in samples if s['label']==0)} safe)")
    return samples


# ============================================================
# EVALUATION CHÍNH
# ============================================================

def evaluate(samples: list, model: str, cwe: str,
             prompt_mode: str = "standard",
             output_file: str = "results.json") -> dict:

    use_slice = prompt_mode.startswith("sliced")
    use_cot   = prompt_mode.endswith("cot")
    cwe_label = f"CWE-{cwe}"

    # CoT sinh text dài hơn → cần timeout cao hơn
    call_timeout = 240 if use_cot else 120

    print(f"\n{'='*60}")
    print(f"  Model    : {model}")
    print(f"  CWE      : {cwe_label}")
    print(f"  Prompt   : {prompt_mode.upper()}")
    print(f"  Slicing  : {'ON' if use_slice else 'OFF'}")
    print(f" Normalization: {'OFF' if prompt_mode == 'raw_baseline' else 'ON'}")
    print(f"  Samples  : {len(samples)}")
    print(f"  Timeout  : {call_timeout}s/call")
    print(f"{'='*60}\n")

    y_true = []
    y_pred = []
    detailed_results = []
    errors = 0
    compression_ratios = []
    start_time = time.time()

    for i, sample in enumerate(tqdm(samples, desc="Evaluating")):
        code       = sample["code"]
        true_label = sample["label"]

        if prompt_mode == "raw_baseline":
            # Baseline: không slicing, không normalization
            code_input = code
        else:
            # Áp dụng slicing nếu cần
            if use_slice:
                code_input = simple_slice(code, cwe)
                stats = slice_stats(code, code_input)
                compression_ratios.append(stats["compression_ratio"])
            else:
                code_input = code

            # Chỉ áp dụng chuẩn hóa nếu KHÔNG phải raw_baseline
            code_input = normalize_code(code_input)

        # Chọn prompt
        if prompt_mode == "raw_baseline":
            prompt = f"Analyze this PHP code for CWE-{cwe} vulnerabilities. Answer VULNERABLE or SAFE only. Code: \n{code_input}"
        elif use_slice:
            prompt = build_prompt_sliced(code_input, cwe, use_cot=use_cot)
        elif use_cot:
            prompt = build_prompt_cot(code_input, cwe)
        else:
            prompt = build_prompt_standard(code_input, cwe)

        # Gọi model
        raw_output = call_ollama(prompt, model, timeout=call_timeout)
        
        # Xử lý kết quả
        if raw_output == "TIMEOUT":
            if prompt_mode == "raw_baseline":
                # Baseline gốc không được phép áp dụng kỹ thuật cắt ngắn code khi chạy lại
                errors += 1
                pred_label = LABEL_SAFE  # Hoặc lấy ngẫu nhiên random.choice([0, 1])
            else:
                # Chỉ các chế độ tối ưu mới được dùng tính năng fallback slice 500 ký tự
                fallback_prompt = (
                    f"Is this PHP code vulnerable to {cwe_label}? "
                    f"Answer VULNERABLE or SAFE only.\n"
                    f"```php\n{code_input[:500]}\n```"
                )
                raw_output = call_ollama(fallback_prompt, model, timeout=60)
            if raw_output in ("TIMEOUT", "ERROR"):
                errors += 1
                pred_label = LABEL_SAFE
            else:
                pred_label = parse_prediction(raw_output)
        elif raw_output == "ERROR":
            errors += 1
            pred_label = LABEL_SAFE
        else:
            pred_label = parse_prediction(raw_output)

        y_true.append(true_label)
        y_pred.append(pred_label)

        detailed_results.append({
            "index"          : i,
            "filename"       : sample.get("filename", ""),
            "true_label"     : true_label,
            "pred_label"     : pred_label,
            "raw_output"     : raw_output[:800],
            "code_preview"   : code[:150],
            "sliced_preview" : code_input[:150] if use_slice else "",
        })

        if (i + 1) % 10 == 0:
            current_f1 = f1_score(y_true, y_pred, zero_division=0)
            print(f"  [{i+1}/{len(samples)}] F1 tạm thời: {current_f1:.4f}")

    elapsed = time.time() - start_time

    accuracy  = accuracy_score(y_true, y_pred)
    f1        = f1_score(y_true, y_pred, zero_division=0)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall    = recall_score(y_true, y_pred, zero_division=0)
    cm        = confusion_matrix(y_true, y_pred).tolist()
    avg_compression = (
        round(sum(compression_ratios) / len(compression_ratios), 3)
        if compression_ratios else 1.0
    )

    print(f"\n{'='*60}")
    print(f"  KẾT QUẢ — {cwe_label} | {model} | {prompt_mode.upper()}")
    print(f"{'='*60}")
    print(f"  Accuracy        : {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  F1-Score        : {f1:.4f}")
    print(f"  Precision       : {precision:.4f}")
    print(f"  Recall          : {recall:.4f}")
    print(f"  Errors          : {errors}/{len(samples)}")
    print(f"  Time            : {elapsed:.1f}s ({elapsed/len(samples):.1f}s/sample)")
    if use_slice:
        print(f"  Avg compression : {avg_compression:.3f} ({avg_compression*100:.1f}% of original)")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    print(f"\n{classification_report(y_true, y_pred, target_names=['SAFE', 'VULNERABLE'], zero_division=0)}")

    paper_results = {
        "79": {"f1": 0.8368, "accuracy": 0.9147},  # Tương ứng F1 = 83.68%, Acc = 91.47% trong Table 1
        "89": {"f1": 0.7874, "accuracy": 0.9235},  # Tương ứng F1 = 78.74%, Acc = 92.35% trong Table 1
    }
    if cwe in paper_results:
        paper = paper_results[cwe]
        print(f"  So sánh paper (CodeLlama-7B fine-tuned):")
        print(f"    F1  : paper={paper['f1']:.4f} | ours={f1:.4f} | {f1-paper['f1']:+.4f}")
        print(f"    Acc : paper={paper['accuracy']:.4f} | ours={accuracy:.4f} | {accuracy-paper['accuracy']:+.4f}")
    print(f"{'='*60}\n")

    output = {
        "config": {
            "model"                 : model,
            "cwe"                   : cwe,
            "prompt_mode"           : prompt_mode,
            "use_slice"             : use_slice,
            "use_normalization" : False if prompt_mode == "raw_baseline" else True,
            "num_samples"           : len(samples),
            "elapsed_seconds"       : round(elapsed, 1),
            "avg_compression_ratio" : avg_compression,
        },
        "metrics": {
            "accuracy"         : round(accuracy, 4),
            "f1_score"         : round(f1, 4),
            "precision"        : round(precision, 4),
            "recall"           : round(recall, 4),
            "confusion_matrix" : cm,
            "errors"           : errors,
        },
        "detailed_results": detailed_results,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"[INFO] Saved → {output_file}")
    return output["metrics"]


# ============================================================
# SO SÁNH 4 MODES
# ============================================================

def compare_prompts(samples: list, model: str, cwe: str):
    modes = ["standard", "cot", "sliced_standard", "sliced_cot"]

    print("\n" + "="*60)
    print("  SO SÁNH 4 MODES: Standard / CoT / Sliced / Sliced+CoT")
    print("="*60)

    results = {}
    for mode in modes:
        print(f"\n▶ Đang chạy: {mode.upper()}")
        metrics = evaluate(
            samples, model, cwe,
            prompt_mode=mode,
            output_file=f"results_cwe{cwe}_{mode}.json"
        )
        results[mode] = metrics

    print("\n" + "="*60)
    print("  TỔNG KẾT SO SÁNH 4 MODES")
    print("="*60)
    print(f"  {'Metric':<12} {'Standard':>10} {'CoT':>10} {'Sliced':>10} {'Sliced+CoT':>12}")
    print(f"  {'-'*56}")
    for metric in ["accuracy", "f1_score", "precision", "recall"]:
        vals = [results[m][metric] for m in modes]
        best = max(vals)
        row  = f"  {metric:<12}"
        for v in vals:
            mark = " ★" if v == best else "  "
            row += f" {v:>8.4f}{mark}"
        print(row)
    print("="*60)

    paper = {"79": 0.7368, "89": 0.8000}
    if cwe in paper:
        best_f1 = max(results[m]["f1_score"] for m in modes)
        print(f"\n  Best F1 của nhóm : {best_f1:.4f}")
        print(f"  Paper F1         : {paper[cwe]:.4f}")
        print(f"  Gap              : {best_f1 - paper[cwe]:+.4f}")
    print("="*60)

    return results


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="RealVul - Ollama Offline Evaluation")
    parser.add_argument("--mode", type=str, default="standard",
                        choices=["standard", "cot", "sliced_standard",
                                 "sliced_cot", "compare", "raw_baseline"])
    parser.add_argument("--cwe", type=str, default="79", choices=["79", "89"])
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL)
    parser.add_argument("--dataset_dir", type=str,
                        default=r"data\dataset\dataset_final_sorted\CWE-{cwe}\php")
    parser.add_argument("--max_samples", type=int, default=None)
    parser.add_argument("--max_file_kb", type=int, default=8)
    # parser.add_argument("--mode", type=str, default="standard",
    #                     choices=["standard", "cot", "sliced_standard",
    #                              "sliced_cot", "compare"])
    parser.add_argument("--output", type=str, default=None)

    args = parser.parse_args()

    os.makedirs("results", exist_ok=True)

    dataset_dir = args.dataset_dir.replace("{cwe}", args.cwe)

    print(f"[INFO] Loading: {dataset_dir}")
    samples = load_dataset_from_dir(dataset_dir, args.cwe,
                                    max_samples=args.max_samples,
                                    max_file_kb=args.max_file_kb)
    if not samples:
        print("[LỖI] Không có samples!")
        return

    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=5)
        models_available = [m["name"] for m in resp.json().get("models", [])]
        print(f"[INFO] Ollama OK. Models: {models_available}")
        if args.model not in models_available:
            print(f"[WARN] Model '{args.model}' chưa pull! Chạy: ollama pull {args.model}")
    except Exception:
        print("[LỖI] Ollama chưa chạy! Chạy: ollama serve")
        return

    if args.mode == "compare":
        compare_prompts(samples, args.model, args.cwe)
    else:
        output_file = (
            args.output or
            f"results/results_cwe{args.cwe}_{args.mode}_"
            f"{args.model.replace(':', '_').replace('.', '_')}.json"
        )
        evaluate(samples, args.model, args.cwe,
                 prompt_mode=args.mode,
                 output_file=output_file)


if __name__ == "__main__":
    main()