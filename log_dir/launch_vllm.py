#!/usr/bin/env python3
import subprocess
import sys
import os

def main():
    os.environ["CUDA_VISIBLE_DEVICES"] = "4,5,6,7"

    cmd = [
        sys.executable, "-m", "vllm.entrypoints.openai.api_server",

        "--model", "/data/model/Qwen--Qwen3-30B-A3B-Instruct-2507",

        "--tensor-parallel-size", "4",
        "--max-model-len", "8192",
        "--dtype", "bfloat16",
        "--gpu-memory-utilization", "0.7",
        "--max-num-seqs", "16",

        "--disable-log-requests",

        "--host", "0.0.0.0",
        "--port", "8001",
    ]

    print("[run_vllm] launching vLLM server...")
    print(" ".join(cmd), flush=True)

    subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()
