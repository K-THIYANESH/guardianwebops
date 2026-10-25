import os
from pathlib import Path

from guardian_swarm.utils.paths import PROJECT_ROOT, MODELS_DIR, DATA_DIR, STATE_FILE


class Settings:
    def __init__(self) -> None:
        self.project_root = PROJECT_ROOT
        self.data_dir = DATA_DIR
        self.models_dir = MODELS_DIR
        self.state_file = STATE_FILE
        self.log_dir = self.data_dir / "logs"
        self.artifacts_dir = self.project_root / "artifacts"
        self.model_name = os.getenv("GUARDIAN_MODEL_NAME", "microsoft/Phi-3.5-mini-instruct")
        self.fallback_model_name = os.getenv("GUARDIAN_FALLBACK_MODEL_NAME", "HuggingFaceTB/SmolLM2-1.7B-Instruct")
        self.cache_dir = os.getenv("GUARDIAN_CACHE_DIR", str(self.models_dir))
        self.use_cuda = os.getenv("GUARDIAN_USE_CUDA", "True").lower() == "true"
        self.max_new_tokens = int(os.getenv("GUARDIAN_MAX_NEW_TOKENS", "150"))
        self.temperature = float(os.getenv("GUARDIAN_TEMPERATURE", "0.2"))
        self.do_sample = os.getenv("GUARDIAN_DO_SAMPLE", "True").lower() == "true"
        self.repetition_penalty = float(os.getenv("GUARDIAN_REPETITION_PENALTY", "1.1"))
        self.force_heuristics = self._resolve_force_heuristics()

    def _resolve_force_heuristics(self) -> bool:
        env_value = os.getenv("GUARDIAN_FORCE_HEURISTICS")
        if env_value is not None:
            return env_value.lower() == "true"
        from guardian_swarm.utils.memory import is_cuda_available
        return not is_cuda_available()

    def as_dict(self) -> dict:
        return {
            "project_root": str(self.project_root),
            "data_dir": str(self.data_dir),
            "models_dir": str(self.models_dir),
            "state_file": str(self.state_file),
            "log_dir": str(self.log_dir),
            "artifacts_dir": str(self.artifacts_dir),
            "model_name": self.model_name,
            "fallback_model_name": self.fallback_model_name,
            "cache_dir": self.cache_dir,
            "use_cuda": self.use_cuda,
            "max_new_tokens": self.max_new_tokens,
            "temperature": self.temperature,
            "do_sample": self.do_sample,
            "repetition_penalty": self.repetition_penalty,
            "force_heuristics": self.force_heuristics,
        }


settings = Settings()
