@echo off
echo ========================================
echo   RealVul Full Experiment
echo   5 models x 2 CWE x 4 modes = 40 runs
echo   Samples: 100 (50 vuln + 50 safe)
echo ========================================

:: ============================================================
:: CWE-79 (100 samples)
:: ============================================================

echo.
echo [CWE-79] qwen2.5-coder:7b ...
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode standard        --model qwen2.5-coder:7b    --output results\qwen_79_standard.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode cot             --model qwen2.5-coder:7b    --output results\qwen_79_cot.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode sliced_standard --model qwen2.5-coder:7b    --output results\qwen_79_sliced_standard.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode sliced_cot      --model qwen2.5-coder:7b    --output results\qwen_79_sliced_cot.json

echo [CWE-79] codellama:7b ...
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode standard        --model codellama:7b        --output results\codellama_79_standard.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode cot             --model codellama:7b        --output results\codellama_79_cot.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode sliced_standard --model codellama:7b        --output results\codellama_79_sliced_standard.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode sliced_cot      --model codellama:7b        --output results\codellama_79_sliced_cot.json

echo [CWE-79] deepseek-coder:6.7b ...
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode standard        --model deepseek-coder:6.7b --output results\deepseek_79_standard.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode cot             --model deepseek-coder:6.7b --output results\deepseek_79_cot.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode sliced_standard --model deepseek-coder:6.7b --output results\deepseek_79_sliced_standard.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode sliced_cot      --model deepseek-coder:6.7b --output results\deepseek_79_sliced_cot.json

echo [CWE-79] llama3.2:3b ...
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode standard        --model llama3.2:3b         --output results\llama_79_standard.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode cot             --model llama3.2:3b         --output results\llama_79_cot.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode sliced_standard --model llama3.2:3b         --output results\llama_79_sliced_standard.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode sliced_cot      --model llama3.2:3b         --output results\llama_79_sliced_cot.json

echo [CWE-79] phi3.5:3.8b ...
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode standard        --model phi3.5:3.8b         --output results\phi_79_standard.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode cot             --model phi3.5:3.8b         --output results\phi_79_cot.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode sliced_standard --model phi3.5:3.8b         --output results\phi_79_sliced_standard.json
python ollama_eval.py --cwe 79 --dataset_dir "data\dataset\dataset_final_sorted\CWE-79\php" --max_samples 100 --mode sliced_cot      --model phi3.5:3.8b         --output results\phi_79_sliced_cot.json

:: ============================================================
:: CWE-89 (100 samples)
:: ============================================================

echo.
echo [CWE-89] qwen2.5-coder:7b ...
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode standard        --model qwen2.5-coder:7b    --output results\qwen_89_standard.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode cot             --model qwen2.5-coder:7b    --output results\qwen_89_cot.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode sliced_standard --model qwen2.5-coder:7b    --output results\qwen_89_sliced_standard.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode sliced_cot      --model qwen2.5-coder:7b    --output results\qwen_89_sliced_cot.json

echo [CWE-89] codellama:7b ...
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode standard        --model codellama:7b        --output results\codellama_89_standard.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode cot             --model codellama:7b        --output results\codellama_89_cot.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode sliced_standard --model codellama:7b        --output results\codellama_89_sliced_standard.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode sliced_cot      --model codellama:7b        --output results\codellama_89_sliced_cot.json

echo [CWE-89] deepseek-coder:6.7b ...
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode standard        --model deepseek-coder:6.7b --output results\deepseek_89_standard.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode cot             --model deepseek-coder:6.7b --output results\deepseek_89_cot.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode sliced_standard --model deepseek-coder:6.7b --output results\deepseek_89_sliced_standard.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode sliced_cot      --model deepseek-coder:6.7b --output results\deepseek_89_sliced_cot.json

echo [CWE-89] llama3.2:3b ...
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode standard        --model llama3.2:3b         --output results\llama_89_standard.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode cot             --model llama3.2:3b         --output results\llama_89_cot.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode sliced_standard --model llama3.2:3b         --output results\llama_89_sliced_standard.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode sliced_cot      --model llama3.2:3b         --output results\llama_89_sliced_cot.json

echo [CWE-89] phi3.5:3.8b ...
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode standard        --model phi3.5:3.8b         --output results\phi_89_standard.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode cot             --model phi3.5:3.8b         --output results\phi_89_cot.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode sliced_standard --model phi3.5:3.8b         --output results\phi_89_sliced_standard.json
python ollama_eval.py --cwe 89 --dataset_dir "data\dataset\dataset_final_sorted\CWE-89\php" --max_samples 100 --mode sliced_cot      --model phi3.5:3.8b         --output results\phi_89_sliced_cot.json

echo.
echo ========================================
echo   DONE! 40/40 runs completed.
echo ========================================
pause