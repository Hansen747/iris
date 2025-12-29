#!/usr/bin/env python3
import os
import multiprocessing as mp

# 1. 必须在任何进程启动前设置
mp.set_start_method('spawn', force=True)

def worker_main(gpu_id: int):
    """子进程入口：先隔离 GPU，再导入 torch，打印 UUID"""
    # ① 第一个 CUDA 相关动作：设置可见卡
    os.environ['CUDA_VISIBLE_DEVICES'] = str(gpu_id)

    # ② 随后才导入 torch（第一次 CUDA 初始化）
    import torch
    torch.cuda.init()
    props = torch.cuda.get_device_properties(0)   # 逻辑 0
    uuid_str = str(props.uuid)                    # 物理 UUID
    print(f"[gpu_id={gpu_id}] 逻辑设备=0  UUID={uuid_str}")

if __name__ == '__main__':
    # 父进程绝不 import torch / 不调 CUDA
    n_gpu = int(os.popen('nvidia-smi -L | wc -l').read())  # 用 nvidia-smi 查卡数
    procs = [mp.Process(target=worker_main, args=(i,)) for i in range(n_gpu)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()