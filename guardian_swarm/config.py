import os
from dotenv import load_dotenv

# Prevent OpenMP double initialization error on Windows (common in Anaconda/PyTorch environments)
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

# Load environment variables from .env file if present
load_dotenv()

from config.settings import settings

# Backward-compatible configuration aliases
GUARDIAN_MODEL_NAME = settings.model_name
GUARDIAN_FALLBACK_MODEL_NAME = settings.fallback_model_name
GUARDIAN_CACHE_DIR = settings.cache_dir
GUARDIAN_USE_CUDA = settings.use_cuda
GUARDIAN_FORCE_HEURISTICS = settings.force_heuristics
GUARDIAN_MAX_NEW_TOKENS = settings.max_new_tokens
GUARDIAN_TEMPERATURE = settings.temperature
GUARDIAN_DO_SAMPLE = settings.do_sample
GUARDIAN_REPETITION_PENALTY = settings.repetition_penalty


def get_config_summary() -> dict:
    return {
        "primary_model": GUARDIAN_MODEL_NAME,
        "fallback_model": GUARDIAN_FALLBACK_MODEL_NAME,
        "cache_directory": GUARDIAN_CACHE_DIR,
        "cuda_enabled": GUARDIAN_USE_CUDA,
        "force_heuristics_fallback": GUARDIAN_FORCE_HEURISTICS,
        "max_new_tokens": GUARDIAN_MAX_NEW_TOKENS,
        "temperature": GUARDIAN_TEMPERATURE,
        "do_sample": GUARDIAN_DO_SAMPLE,
        "repetition_penalty": GUARDIAN_REPETITION_PENALTY,
    }
