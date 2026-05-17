import os
import time
import json
import random
import argparse
from dotenv import load_dotenv
import requests
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score,
    recall_score, classification_report, confusion_matrix
)
from tqdm import tqdm

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "llama-3.1-8b-instant"

LABEL_VULNERABLE = 1
LABEL_SAFE = 0

# ============================================================
# PROMPT TEMPLATES
# ============================================================

def build_prompt_standard(code_snippet: str, cwe: str) -> str:
    vuln_type = "Cross-Site Scripting (XSS)" if cwe == "79" else "SQL Injection"
    return f"""Analyze the following PHP code snippet for {vuln_type} (CWE-{cwe}) vulnerabilities.

PHP Code:
```php
{code_snippet}
```

Instructions:
- Carefully examine the code for {vuln_type} vulnerabilities
- Consider user input sources, data flows, and output contexts
- Answer ONLY with: VULNERABLE or SAFE
- Do not explain, just output one word

Answer:"""


def build_prompt_cot(code_snippet: str, cwe: str) -> str:
    vuln_type = "Cross-Site Scripting (XSS)" if cwe == "79" else "SQL Injection"
    return f"""You are analyzing PHP code for {vuln_type} (CWE-{cwe}) vulnerabilities.

PHP Code:
```php
{code_snippet}
```

Answer these questions briefly:
1. What user inputs exist? (e.g. $_GET, $_POST)
2. Where does data flow? (e.g. echo, print, SQL)
3. Is there sanitization? (yes/no)

Final verdict (MUST be one word on its own line):
VERDICT:"""


# ============================================================
# PROGRAM SLICING
# ============================================================

def simple_slice(code: str, cwe: str) -> str:
    if cwe == "79":
        sources = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE',
                   '$_SERVER', '$_FILES', '$HTTP_GET_VARS']
        sinks   = ['echo', 'print', 'printf', 'die(', 'exit(',
                   'header(', 'document.write', 'innerHTML']
    else:
        sources = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE',
                   '$_SERVER', '$_FILES']
        sinks   = ['query(', 'execute(', 'mysqli_query', 'mysql_query',
                   'pg_query', 'sqlite_query', 'prepare(']

    lines = code.split('\n')
    selected = set()
    for i, line in enumerate(lines):
        if any(s in line for s in sources + sinks):
            for j in range(max(0, i - 5), min(len(lines), i + 6)):
                selected.add(j)

    if not selected:
        return code
    sliced = [lines[i] for i in sorted(selected)]
    return '\n'.join(sliced) if len(sliced) >= 3 else code


def build_prompt_sliced(code_snippet: str, cwe: str, use_cot: bool = False) -> str:
    vuln_type = "Cross-Site Scripting (XSS)" if cwe == "79" else "SQL Injection"
    if use_cot:
        return f"""You are analyzing a PHP code slice (extracted relevant lines only) for {vuln_type} (CWE-{cwe}).

Relevant PHP code slice:
```php
{code_snippet}
```

Answer these questions briefly:
1. What user inputs exist? (e.g. $_GET, $_POST)
2. Where does data flow? (e.g. echo, print, SQL)
3. Is there sanitization? (yes/no)

Final verdict (MUST be one word on its own line):
VERDICT:"""
    else:
        return f"""Analyze this PHP code slice for CWE-{cwe} vulnerabilities.
This is a program slice containing only the relevant source/sink lines.

PHP code slice:
```php
{code_snippet}
```

Instructions:
- Answer ONLY with: VULNERABLE or SAFE
- Do not explain, just output one word

Answer:"""


# ============================================================
# GỌI GROQ API
# ============================================================

def call_groq(prompt: str, model_name: str, retries: int = 3) -> str:
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model_name,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 300,
    }

    for attempt in range(retries):
        try:
            response = requests.post(GROQ_URL, headers=headers,
                                     json=payload, timeout=30)
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"].strip()
            elif response.status_code == 429:
                wait = 30 * (attempt + 1)
                print(f"\n[RATE LIMIT] Chờ {wait}s... (lần {attempt+1}/{retries})")
                time.sleep(wait)
            else:
                print(f"\n[LỖI {response.status_code}] {response.text[:200]}")
                return "ERROR"
        except Exception as e:
            print(f"\n[LỖI] {e}")
            return "ERROR"
    return "ERROR"


def parse_prediction(raw_output: str) -> int:
    for line in raw_output.upper().splitlines():
        line = line.strip()
        if line.startswith("VERDICT:"):
            verdict = line.replace("VERDICT:", "").strip()
            if "VULNERABLE" in verdict:
                return LABEL_VULNERABLE
            if "SAFE" in verdict:
                return LABEL_SAFE

    text = raw_output.upper()
    if "VULNERABLE" in text:
        return LABEL_VULNERABLE
    if "SAFE" in text:
        return LABEL_SAFE

    for kw in ["YES", "VULN", "INSECURE", "DANGER", "XSS", "INJECTION"]:
        if kw in text:
            return LABEL_VULNERABLE
    for kw in ["NO", "CLEAN", "SECURE", "PROTECTED", "SANITIZED"]:
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
        raise FileNotFoundError(f"Không tìm thấy: {dataset_dir}")

    all_files = [f for f in os.listdir(dataset_dir)
                 if os.path.isfile(os.path.join(dataset_dir, f))]
    print(f"[INFO] Tổng số file: {len(all_files)}")

    for filename in all_files:
        filepath = os.path.join(dataset_dir, filename)
        if filename.startswith("bad_"):
            label = LABEL_VULNERABLE
        elif filename.startswith(("good_", "fix_", "safe_")):
            label = LABEL_SAFE
        else:
            continue

        size = os.path.getsize(filepath)
        if size <= 14 or size > max_file_kb * 1024:
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read().strip()
            if code:
                samples.append({"code": code, "label": label,
                                 "filename": filename})
        except Exception as e:
            print(f"[WARN] {filename}: {e}")

    print(f"[INFO] Sau lọc còn: {len(samples)} samples")

    if max_samples:
        vuln = [s for s in samples if s["label"] == LABEL_VULNERABLE]
        safe = [s for s in samples if s["label"] == LABEL_SAFE]
        random.seed(42)
        random.shuffle(vuln)
        random.shuffle(safe)
        half = max_samples // 2
        samples = vuln[:half] + safe[:half] if safe else vuln[:max_samples]
        random.shuffle(samples)

    print(f"[INFO] Đã load {len(samples)} samples "
          f"({sum(1 for s in samples if s['label']==1)} vulnerable, "
          f"{sum(1 for s in samples if s['label']==0)} safe)")
    return samples


# ============================================================
# EVALUATION
# ============================================================

def evaluate(samples: list, model_name: str, cwe: str,
             prompt_mode: str = "standard",
             output_file: str = "results.json") -> dict:

    use_slice = prompt_mode.startswith("sliced")
    use_cot   = prompt_mode.endswith("cot")

    print(f"\n{'='*60}")
    print(f"  Model   : {model_name} (ONLINE - Groq)")
    print(f"  CWE     : CWE-{cwe}")
    print(f"  Prompt  : {prompt_mode.upper()}")
    print(f"  Slicing : {'ON' if use_slice else 'OFF'}")
    print(f"  Samples : {len(samples)}")
    print(f"{'='*60}\n")

    y_true, y_pred = [], []
    detailed_results = []
    errors = 0
    start_time = time.time()

    for i, sample in enumerate(tqdm(samples, desc="Evaluating")):
        code = sample["code"]
        true_label = sample["label"]

        code_input = simple_slice(code, cwe) if use_slice else code

        if use_slice:
            prompt = build_prompt_sliced(code_input, cwe, use_cot=use_cot)
        elif use_cot:
            prompt = build_prompt_cot(code_input, cwe)
        else:
            prompt = build_prompt_standard(code_input, cwe)

        # Groq free: 30 req/phút → 2s/request là an toàn
        time.sleep(4)

        raw_output = call_groq(prompt, model_name)

        if raw_output == "ERROR":
            errors += 1
            pred_label = LABEL_SAFE
        else:
            pred_label = parse_prediction(raw_output)

        y_true.append(true_label)
        y_pred.append(pred_label)
        detailed_results.append({
            "index": i,
            "filename": sample.get("filename", ""),
            "true_label": true_label,
            "pred_label": pred_label,
            "raw_output": raw_output[:300],
        })

        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{len(samples)}] F1 tạm thời: "
                  f"{f1_score(y_true, y_pred, zero_division=0):.4f}")

    elapsed = time.time() - start_time
    accuracy  = accuracy_score(y_true, y_pred)
    f1        = f1_score(y_true, y_pred, zero_division=0)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall    = recall_score(y_true, y_pred, zero_division=0)
    cm        = confusion_matrix(y_true, y_pred).tolist()

    print(f"\n{'='*60}")
    print(f"  KẾT QUẢ — CWE-{cwe} | {model_name} | {prompt_mode.upper()}")
    print(f"{'='*60}")
    print(f"  Accuracy  : {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  F1-Score  : {f1:.4f}")
    print(f"  Precision : {precision:.4f}")
    print(f"  Recall    : {recall:.4f}")
    print(f"  Errors    : {errors}/{len(samples)}")
    print(f"  Time      : {elapsed:.1f}s ({elapsed/len(samples):.1f}s/sample)")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    print(f"\n{classification_report(y_true, y_pred, target_names=['SAFE','VULNERABLE'], zero_division=0)}")

    paper = {"79": {"f1": 0.7368, "accuracy": 0.7500},
             "89": {"f1": 0.8000, "accuracy": 0.8125}}
    if cwe in paper:
        p = paper[cwe]
        print(f"  So sánh paper:")
        print(f"    F1  : paper={p['f1']:.4f} | ours={f1:.4f} | {f1-p['f1']:+.4f}")
        print(f"    Acc : paper={p['accuracy']:.4f} | ours={accuracy:.4f} | {accuracy-p['accuracy']:+.4f}")
    print(f"{'='*60}\n")

    output = {
        "config": {"model": model_name, "cwe": cwe,
                   "prompt_mode": prompt_mode, "online": True,
                   "provider": "groq",
                   "num_samples": len(samples),
                   "elapsed_seconds": round(elapsed, 1)},
        "metrics": {"accuracy": round(accuracy, 4), "f1_score": round(f1, 4),
                    "precision": round(precision, 4), "recall": round(recall, 4),
                    "confusion_matrix": cm, "errors": errors},
        "detailed_results": detailed_results
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"[INFO] Saved → {output_file}")
    return output["metrics"]


def compare_prompts(samples, model_name, cwe):
    modes = ["standard", "cot", "sliced_standard", "sliced_cot"]
    print("\n" + "="*60)
    print("  SO SÁNH 4 MODES — Groq Online")
    print("="*60)

    results = {}
    for mode in modes:
        print(f"\n▶ Đang chạy: {mode.upper()}")
        metrics = evaluate(samples, model_name, cwe,
                           prompt_mode=mode,
                           output_file=f"results_groq_cwe{cwe}_{mode}.json")
        results[mode] = metrics

    print("\n" + "="*60)
    print("  TỔNG KẾT")
    print("="*60)
    print(f"  {'Metric':<12} {'Standard':>10} {'CoT':>10} {'Sliced':>10} {'Sliced+CoT':>12}")
    print(f"  {'-'*56}")
    for metric in ["accuracy", "f1_score", "precision", "recall"]:
        vals = [results[m][metric] for m in modes]
        best = max(vals)
        row = f"  {metric:<12}"
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
    parser = argparse.ArgumentParser(description="RealVul - Groq Online Evaluation")
    parser.add_argument("--cwe", type=str, default="79", choices=["79", "89"])
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL)
    parser.add_argument("--dataset_dir", type=str,
                        default=r"data\dataset\dataset_final_sorted\CWE-{cwe}\php")
    parser.add_argument("--max_samples", type=int, default=100)
    parser.add_argument("--max_file_kb", type=int, default=8)
    parser.add_argument("--mode", type=str, default="standard",
                        choices=["standard", "cot", "sliced_standard",
                                 "sliced_cot", "compare"])
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    if not GROQ_API_KEY:
        print("[LỖI] Chưa có GROQ_API_KEY trong file .env!")
        return

    dataset_dir = args.dataset_dir.replace("{cwe}", args.cwe)
    print(f"[INFO] Loading: {dataset_dir}")
    samples = load_dataset_from_dir(dataset_dir, args.cwe,
                                    max_samples=args.max_samples,
                                    max_file_kb=args.max_file_kb)
    if not samples:
        print("[LỖI] Không có samples!")
        return

    if args.mode == "compare":
        compare_prompts(samples, args.model, args.cwe)
    else:
        output_file = args.output or f"results_groq_cwe{args.cwe}_{args.mode}.json"
        evaluate(samples, args.model, args.cwe,
                 prompt_mode=args.mode,
                 output_file=output_file)


if __name__ == "__main__":
    main()