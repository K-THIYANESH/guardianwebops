import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
import sys

def get_gpu_memory_usage() -> str:
    """
    Returns a string summarizing the current GPU memory allocated/reserved
    and total system GPU utilization if CUDA is available.
    """
    try:
        import torch
        if torch.cuda.is_available():
            allocated = torch.cuda.memory_allocated() / (1024 ** 2)
            reserved = torch.cuda.memory_reserved() / (1024 ** 2)
            try:
                free, total = torch.cuda.mem_get_info()
                total_mb = total / (1024 ** 2)
                free_mb = free / (1024 ** 2)
                used_mb = total_mb - free_mb
                return (f"Allocated: {allocated:.2f} MB | Reserved: {reserved:.2f} MB | "
                        f"GPU VRAM Used: {used_mb:.2f} / {total_mb:.2f} MB")
            except Exception as e:
                return f"Allocated: {allocated:.2f} MB | Reserved: {reserved:.2f} MB"
        else:
            return "CUDA not available (CPU execution mode)"
    except ImportError:
        return "PyTorch not installed"

def is_cuda_available() -> bool:
    """
    Safe check if PyTorch is installed and CUDA is active.
    """
    try:
        import torch
        return torch.cuda.is_available()
    except ImportError:
        return False
