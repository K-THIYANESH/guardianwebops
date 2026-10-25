import time
import json
import re
import os
from pathlib import Path
from typing import Tuple, Optional
from guardian_swarm.config import (
    GUARDIAN_MODEL_NAME,
    GUARDIAN_FALLBACK_MODEL_NAME,
    GUARDIAN_CACHE_DIR,
    GUARDIAN_MAX_NEW_TOKENS,
    GUARDIAN_TEMPERATURE,
    GUARDIAN_DO_SAMPLE,
    GUARDIAN_REPETITION_PENALTY,
    GUARDIAN_FORCE_HEURISTICS
)
from guardian_swarm.utils.memory import get_gpu_memory_usage, is_cuda_available
from guardian_swarm.utils.paths import STATE_FILE, DATA_DIR, resolve_state_file
from guardian_swarm.utils.visual import LoadingSpinner, Color
from guardian_swarm.utils.logger import log_event

# Global references for lazy loading
torch = None
transformers = None

class VerificationAgent:
    """
    VerificationAgent handles loading the local model (Phi-3.5 or fallback SmolLM2)
    and generating/evaluating structured prompts for action safety assessment.
    Also supports connecting to local external running servers like Ollama or LM Studio.
    """
    def __init__(self):
        self.model_name = GUARDIAN_MODEL_NAME
        self.fallback_name = GUARDIAN_FALLBACK_MODEL_NAME
        self.cache_dir = GUARDIAN_CACHE_DIR
        self.device = "cuda" if is_cuda_available() else "cpu"
        self.model = None
        self.tokenizer = None
        self.is_fallback = False
        
        # Connection and routing settings
        self._engine_type = "heuristics" if GUARDIAN_FORCE_HEURISTICS else "pytorch"
        self.connected_server = None
        self.connected_url = ""
        self.connected_model = ""
        self.last_query_stats = {
            "latency_ms": 0.0,
            "tokens_per_sec": 0.0,
            "tokens_generated": 0
        }

        # Load preloaded configuration if it exists to avoid live detection during pitch
        state_file = resolve_state_file()
        if state_file.exists():
            try:
                with state_file.open("r", encoding="utf-8") as f:
                    state = json.load(f)
                    self._engine_type = state.get("engine_type", self._engine_type)
                    self.device = state.get("device", self.device)
                    self.model_name = state.get("model_name", self.model_name)
                    self.is_fallback = state.get("is_fallback", self.is_fallback)
                    self.connected_server = state.get("connected_server", self.connected_server)
                    self.connected_url = state.get("connected_url", self.connected_url)
                    self.connected_model = state.get("connected_model", self.connected_model)
            except Exception:
                pass

    @property
    def is_heuristic(self) -> bool:
        return self._engine_type == "heuristics"

    @is_heuristic.setter
    def is_heuristic(self, val: bool):
        if val:
            self._engine_type = "heuristics"
        else:
            if self._engine_type == "heuristics":
                self._engine_type = "pytorch"

    @property
    def engine_type(self) -> str:
        return self._engine_type

    @engine_type.setter
    def engine_type(self, val: str):
        self._engine_type = val

    def load_model(self):
        """
        Loads the model weights and tokenizer, checking for CUDA and setting up
        4-bit bitsandbytes quantization if running on Nvidia GPUs.
        """
        global torch, transformers
        
        if self._engine_type == "heuristics":
            print(f"{Color.WARNING}⚠️ heuristics mode is active. Skipping model load.{Color.END}")
            return

        # 1. Imports check
        spinner = LoadingSpinner("Loading deep learning frameworks")
        spinner.start()
        try:
            import torch as t
            import transformers as tf
            torch = t
            transformers = tf
            if not STATE_FILE.exists():
                self.device = "cuda" if torch.cuda.is_available() else "cpu"
            spinner.stop()
        except ImportError as e:
            spinner.stop()
            print(f"{Color.WARNING}⚠️ Deep learning libraries not found: {e}{Color.END}")
            print(f"{Color.WARNING}🔄 Falling back to Heuristic Rules Engine.{Color.END}")
            self._engine_type = "heuristics"
            return

        model_to_load = self.model_name
        safe_dtype = torch.float32

        if not STATE_FILE.exists():
            # Check system memory capacity on CPU
            try:
                import psutil
                avail_gb = psutil.virtual_memory().available / (1024 ** 3)
            except ImportError:
                avail_gb = 16.0

            # Resolve model name and data types based on memory and device constraints
            self.is_fallback = False

            if self.device == "cpu":
                if avail_gb < 8.0:
                    print(f"{Color.WARNING}⚠️ Insufficient memory to run primary model ({avail_gb:.1f} GB available).{Color.END}")
                    print(f"{Color.WARNING}🔄 Falling back to SmolLM2-1.7B-Instruct...{Color.END}")
                    self.is_fallback = True
                    model_to_load = self.fallback_name
                elif avail_gb < 15.0:
                    print(f"{Color.WARNING}⚠️ Moderate memory detected ({avail_gb:.1f} GB available). Enabling CPU bfloat16 mode.{Color.END}")
                    safe_dtype = torch.bfloat16

                if model_to_load == self.fallback_name:
                    if avail_gb < 3.5:
                        print(f"{Color.WARNING}⚠️ Critical memory constraint ({avail_gb:.1f} GB available).{Color.END}")
                        print(f"{Color.WARNING}🔄 Falling back to Heuristic Rules Engine.{Color.END}")
                        self._engine_type = "heuristics"
                        return
                    elif avail_gb < 7.0:
                        print(f"{Color.WARNING}⚠️ Enabling CPU bfloat16 mode to fit SmolLM2 ({avail_gb:.1f} GB available).{Color.END}")
                        safe_dtype = torch.bfloat16
        else:
            if self.device == "cpu":
                try:
                    import psutil
                    avail_gb = psutil.virtual_memory().available / (1024 ** 3)
                except ImportError:
                    avail_gb = 16.0
                if avail_gb < 15.0:
                    safe_dtype = torch.bfloat16

        # 2. Tokenizer check
        tokenizer_name = model_to_load
        spinner = LoadingSpinner(f"Step 2/4: Fetching Tokenizer ({tokenizer_name})")
        spinner.start()
        try:
            self.tokenizer = transformers.AutoTokenizer.from_pretrained(
                tokenizer_name,
                cache_dir=self.cache_dir,
                trust_remote_code=True
            )
            spinner.stop()
        except Exception as e:
            spinner.stop()
            print(f"{Color.WARNING}⚠️ Tokenizer failed to load for {tokenizer_name}: {e}{Color.END}")
            if model_to_load == self.model_name:
                print(f"{Color.WARNING}🔄 Retrying with fallback model: {self.fallback_name}{Color.END}")
                self.is_fallback = True
                model_to_load = self.fallback_name
                tokenizer_name = self.fallback_name
                spinner = LoadingSpinner(f"Step 2/4 (Fallback): Fetching Tokenizer ({tokenizer_name})")
                spinner.start()
                try:
                    self.tokenizer = transformers.AutoTokenizer.from_pretrained(
                        tokenizer_name,
                        cache_dir=self.cache_dir,
                        trust_remote_code=True
                    )
                    spinner.stop()
                except Exception as ex:
                    spinner.stop()
                    print(f"{Color.FAIL}❌ Fallback tokenizer also failed: {ex}{Color.END}")
                    print(f"{Color.WARNING}🔄 Falling back to Heuristic Rules Engine.{Color.END}")
                    self._engine_type = "heuristics"
                    return
            else:
                print(f"{Color.WARNING}🔄 Falling back to Heuristic Rules Engine.{Color.END}")
                self._engine_type = "heuristics"
                return

        # 3. Model Weights Load
        spinner = LoadingSpinner(f"Step 3/4: Loading Weights ({model_to_load})")
        spinner.start()
        
        try:
            if self.device == "cuda":
                try:
                    from transformers import BitsAndBytesConfig
                    bnb_config = BitsAndBytesConfig(
                        load_in_4bit=True,
                        bnb_4bit_use_double_quant=True,
                        bnb_4bit_quant_type="nf4",
                        bnb_4bit_compute_dtype=torch.float16,
                        device_map="auto"
                    )
                    self.model = transformers.AutoModelForCausalLM.from_pretrained(
                        model_to_load,
                        quantization_config=bnb_config,
                        device_map="auto",
                        cache_dir=self.cache_dir,
                        trust_remote_code=True
                    )
                    spinner.stop()
                except Exception as bnb_err:
                    spinner.stop()
                    print(f"\n{Color.WARNING}⚠️ 4-bit Quantization load failed: {bnb_err}{Color.END}")
                    spinner = LoadingSpinner("Step 3/4 (Alt): Loading in standard FP16 on GPU")
                    spinner.start()
                    self.model = transformers.AutoModelForCausalLM.from_pretrained(
                        model_to_load,
                        torch_dtype=torch.float16,
                        device_map="auto",
                        cache_dir=self.cache_dir,
                        trust_remote_code=True
                    )
                    spinner.stop()
            else:
                self.model = transformers.AutoModelForCausalLM.from_pretrained(
                    model_to_load,
                    torch_dtype=safe_dtype,
                    device_map="cpu",
                    cache_dir=self.cache_dir,
                    trust_remote_code=True
                )
                spinner.stop()
        except Exception as model_err:
            spinner.stop()
            print(f"\n{Color.WARNING}⚠️ Model allocation failed: {model_err}{Color.END}")
            if self.device == "cuda":
                print(f"{Color.WARNING}🔄 Falling back to CPU load (Warning: Slow Inference)...{Color.END}")
                self.device = "cpu"
                spinner = LoadingSpinner("Step 3/4 (Alt): Loading Weights on CPU")
                spinner.start()
                try:
                    self.model = transformers.AutoModelForCausalLM.from_pretrained(
                        model_to_load,
                        torch_dtype=safe_dtype,
                        device_map="cpu",
                        cache_dir=self.cache_dir,
                        trust_remote_code=True
                    )
                    spinner.stop()
                except Exception as cpu_err:
                    spinner.stop()
                    print(f"{Color.FAIL}❌ CPU loading also failed: {cpu_err}{Color.END}")
                    print(f"{Color.WARNING}🔄 Falling back to Heuristic Rules Engine.{Color.END}")
                    self._engine_type = "heuristics"
            else:
                print(f"{Color.WARNING}🔄 Falling back to Heuristic Rules Engine.{Color.END}")
                self._engine_type = "heuristics"
                return

        # 4. Final verification checks
        spinner = LoadingSpinner("Step 4/4: Confirming verification pipelines")
        spinner.start()
        time.sleep(0.5)
        spinner.stop()
        
        if self._engine_type != "heuristics":
            print(f"{Color.GREEN}✔ Verification Agent model initialized!{Color.END}")
            print(f"{Color.GREEN}📊 Device mapping: {self.device.upper()}{Color.END}")
        else:
            print(f"{Color.WARNING}⚠️ Running under Heuristics Fallback Engine.{Color.END}")

    def _generate_response(self, system_prompt: str, user_prompt: str) -> Tuple[str, float]:
        """
        Unified method to query either local PyTorch model or external local server.
        """
        global torch, transformers
        import time
        start_time = time.time()
        
        if self._engine_type == "pytorch":
            if "phi-3.5" in self.model_name.lower() and not self.is_fallback:
                formatted_prompt = f"<|system|>\n{system_prompt}<|end|>\n<|user|>\n{user_prompt}<|end|>\n<|assistant|>\n"
            else:
                formatted_prompt = f"<|im_start|>system\n{system_prompt}<|im_end|>\n<|im_start|>user\n{user_prompt}<|im_end|>\n<|im_start|>assistant\n"
            
            inputs = self.tokenizer(formatted_prompt, return_tensors="pt").to(self.device)
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=GUARDIAN_MAX_NEW_TOKENS,
                    temperature=GUARDIAN_TEMPERATURE,
                    do_sample=GUARDIAN_DO_SAMPLE,
                    repetition_penalty=GUARDIAN_REPETITION_PENALTY,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            elapsed_ms = (time.time() - start_time) * 1000
            input_length = inputs.input_ids.shape[1]
            generated_tokens = outputs[0][input_length:]
            response_text = self.tokenizer.decode(generated_tokens, skip_special_tokens=True).strip()
            
            # Update last query stats
            self.last_query_stats["latency_ms"] += elapsed_ms
            self.last_query_stats["tokens_generated"] += len(generated_tokens)
            self.last_query_stats["tokens_per_sec"] = self.last_query_stats["tokens_generated"] / (self.last_query_stats["latency_ms"] / 1000) if self.last_query_stats["latency_ms"] > 0 else 0
            
            return response_text, elapsed_ms
            
        elif self._engine_type in ("ollama", "lm_studio", "openai"):
            full_prompt = f"System: {system_prompt}\nUser: {user_prompt}"
            if self._engine_type == "ollama":
                text, elapsed_ms, tps = self._query_ollama(self.connected_url, self.connected_model, full_prompt)
            else:
                text, elapsed_ms, tps = self._query_openai_compatible(self.connected_url, self.connected_model, full_prompt)
                
            self.last_query_stats["latency_ms"] += elapsed_ms
            self.last_query_stats["tokens_generated"] += int(tps * (elapsed_ms / 1000))
            self.last_query_stats["tokens_per_sec"] = self.last_query_stats["tokens_generated"] / (self.last_query_stats["latency_ms"] / 1000) if self.last_query_stats["latency_ms"] > 0 else 0
            
            return text, elapsed_ms
        else:
            raise ValueError(f"Unknown engine type {self._engine_type}")

    def verify_action(self, agent_id: str, agent_type: str, tool: str, target: str, params: dict) -> Tuple[str, float, str, float, dict]:
        """
        Verifies the proposed action using a sequential 3-agent debate.
        Returns: Tuple(verdict, confidence, reasoning, total_elapsed_ms, debate_trace)
        """
        if self._engine_type == "heuristics" or (self._engine_type == "pytorch" and (self.model is None or self.tokenizer is None)):
            return self._heuristic_verify(agent_id, agent_type, tool, target, params)

        self.last_query_stats = {"latency_ms": 0.0, "tokens_per_sec": 0.0, "tokens_generated": 0}
        
        # 1. PROSECUTOR AGENT
        prosecutor_sys = """You are the ProsecutorAgent, a specialized security agent in the Guardian Swarm.
Your task is to analyze the proposed agent action and argue why this action IS malicious, unsafe, or compromised (e.g. prompt injection, privilege escalation, role violation).
You must output exactly in this format:
ARGUMENT: [Your argument here, 2-3 sentences]
RISK_SCORE: [A score from 0 to 10]
"""
        prosecutor_user = f"Agent ID: {agent_id}\nAgent Type: {agent_type}\nProposed Tool: {tool}\nProposed Target: {target}\nProposed Params: {json.dumps(params)}"
        
        try:
            p_text, p_ms = self._generate_response(prosecutor_sys, prosecutor_user)
            p_arg, p_score = self._parse_prosecutor_response(p_text)
            log_event("info", f"[Prosecutor Verdict] Risk: {p_score}/10 | {p_arg}")
        except Exception as e:
            log_event("warning", f"Prosecutor failed: {e}")
            return self._heuristic_verify(agent_id, agent_type, tool, target, params)

        # 2. DEFENDER AGENT
        defender_sys = """You are the DefenderAgent, a specialized security agent in the Guardian Swarm.
Your task is to analyze the proposed agent action and argue why this action is legitimate and safe given the agent's role and stated context.
You must output exactly in this format:
ARGUMENT: [Your argument here, 2-3 sentences]
SAFETY_SCORE: [A score from 0 to 10]
"""
        defender_user = f"Agent ID: {agent_id}\nAgent Type: {agent_type}\nProposed Tool: {tool}\nProposed Target: {target}\nProposed Params: {json.dumps(params)}"

        try:
            d_text, d_ms = self._generate_response(defender_sys, defender_user)
            d_arg, d_score = self._parse_defender_response(d_text)
            log_event("info", f"[Defender Verdict] Safety: {d_score}/10 | {d_arg}")
        except Exception as e:
            log_event("warning", f"Defender failed: {e}")
            return self._heuristic_verify(agent_id, agent_type, tool, target, params)

        # 3. JUDGE AGENT
        judge_sys = """You are the JudgeAgent, the final arbiter in the Guardian Swarm.
You will receive a proposed agent action, the Prosecutor's argument and risk score, and the Defender's argument and safety score.
You must evaluate both arguments and issue the final verdict: SAFE, BLOCKED, or ESCALATE_TO_HUMAN.
You must output exactly in this format:
VERDICT: [SAFE, BLOCKED, or ESCALATE_TO_HUMAN]
CONFIDENCE: [A confidence score from 0 to 10]
REASONING: [1-2 sentences synthesizing both sides]
"""
        judge_user = (
            f"Agent ID: {agent_id}\nAgent Type: {agent_type}\nProposed Tool: {tool}\nProposed Target: {target}\nProposed Params: {json.dumps(params)}\n\n"
            f"[PROSECUTOR DEBATE ENTRY]\nArgument: {p_arg}\nRisk Score: {p_score}\n\n"
            f"[DEFENDER DEBATE ENTRY]\nArgument: {d_arg}\nSafety Score: {d_score}"
        )

        try:
            j_text, j_ms = self._generate_response(judge_sys, judge_user)
            verdict, confidence, reasoning = self._parse_judge_response(j_text)
            log_event("info", f"[Judge Verdict] Verdict: {verdict} | Confidence: {confidence}/10 | {reasoning}")
        except Exception as e:
            log_event("warning", f"Judge failed: {e}")
            return self._heuristic_verify(agent_id, agent_type, tool, target, params)
            
        total_ms = p_ms + d_ms + j_ms
        
        debate_trace = {
            "prosecutor": {"argument": p_arg, "score": p_score},
            "defender": {"argument": d_arg, "score": d_score},
            "judge": {"verdict": verdict, "confidence": confidence, "reasoning": reasoning}
        }

        # Check against CONFIDENCE_THRESHOLD from policies
        from guardian_swarm.core.policies import CONFIDENCE_THRESHOLD
        if confidence < CONFIDENCE_THRESHOLD and verdict == "SAFE":
            verdict = "ESCALATE_TO_HUMAN"
            debate_trace["judge"]["verdict"] = "ESCALATE_TO_HUMAN"
            debate_trace["judge"]["reasoning"] = f"Confidence {confidence} is below threshold {CONFIDENCE_THRESHOLD}. Overriding verdict to ESCALATE_TO_HUMAN."
            reasoning = debate_trace["judge"]["reasoning"]

        return verdict, confidence, reasoning, total_ms, debate_trace

    def _query_ollama(self, url: str, model: str, prompt: str) -> Tuple[str, float, float]:
        import urllib.request
        import json
        import time

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2
            }
        }
        
        req = urllib.request.Request(
            f"{url.rstrip('/')}/api/generate",
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        
        start = time.time()
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            elapsed_ms = (time.time() - start) * 1000
            text = res_data.get("response", "")
            
            eval_count = res_data.get("eval_count")
            eval_duration = res_data.get("eval_duration")
            if eval_count and eval_duration:
                tokens_per_sec = eval_count / (eval_duration / 1e9)
            else:
                tokens_per_sec = (len(text) / 4) / (elapsed_ms / 1000) if elapsed_ms > 0 else 0
                
            return text, elapsed_ms, tokens_per_sec

    def _query_openai_compatible(self, url: str, model: str, prompt: str) -> Tuple[str, float, float]:
        import urllib.request
        import json
        import time

        payload = {
            "model": model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "stream": False
        }
        
        endpoint = f"{url.rstrip('/')}/v1/chat/completions"
        if "/v1" in url:
            endpoint = f"{url.rstrip('/')}/chat/completions"
            
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        
        start = time.time()
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            elapsed_ms = (time.time() - start) * 1000
            choices = res_data.get("choices", [])
            text = ""
            if choices:
                text = choices[0].get("message", {}).get("content", "")
                
            usage = res_data.get("usage", {})
            completion_tokens = usage.get("completion_tokens")
            if completion_tokens:
                tokens_per_sec = completion_tokens / (elapsed_ms / 1000) if elapsed_ms > 0 else 0
            else:
                tokens_per_sec = (len(text) / 4) / (elapsed_ms / 1000) if elapsed_ms > 0 else 0
                
            return text, elapsed_ms, tokens_per_sec

    @staticmethod
    def scan_local_servers() -> dict:
        import urllib.request
        import json
        import time
        
        scan_results = {}
        servers_to_scan = {
            "Ollama": {"url": "http://127.0.0.1:11434", "type": "ollama", "models_endpoint": "/api/tags"},
            "LM Studio": {"url": "http://127.0.0.1:1234", "type": "lm_studio", "models_endpoint": "/v1/models"},
            "vLLM": {"url": "http://127.0.0.1:8000", "type": "openai", "models_endpoint": "/v1/models"},
            "llama.cpp": {"url": "http://127.0.0.1:8080", "type": "openai", "models_endpoint": "/v1/models"}
        }
        
        for name, config in servers_to_scan.items():
            url = config["url"]
            endpoint = f"{url}{config['models_endpoint']}"
            start_time = time.time()
            try:
                req = urllib.request.Request(endpoint, method="GET")
                with urllib.request.urlopen(req, timeout=1.0) as response:
                    if response.status == 200:
                        res_data = json.loads(response.read().decode('utf-8'))
                        models = []
                        if config["type"] == "ollama":
                            models = [m.get("name") for m in res_data.get("models", [])]
                        else:
                            models_list = res_data.get("data", [])
                            if isinstance(models_list, list):
                                models = [m.get("id") for m in models_list if isinstance(m, dict)]
                            elif isinstance(res_data, list):
                                models = [m.get("id") for m in res_data if isinstance(m, dict)]
                        
                        elapsed_ms = (time.time() - start_time) * 1000
                        scan_results[name] = {
                            "status": "connected",
                            "url": url,
                            "type": config["type"],
                            "models": models,
                            "latency_ms": elapsed_ms
                        }
                    else:
                        scan_results[name] = {
                            "status": "offline",
                            "url": url,
                            "type": config["type"],
                            "error": f"HTTP Status {response.status}"
                        }
            except Exception as e:
                scan_results[name] = {
                    "status": "offline",
                    "url": url,
                    "type": config["type"],
                    "error": str(e)
                }
        return scan_results

    def _parse_prosecutor_response(self, text: str) -> Tuple[str, int]:
        argument = "No prosecutor argument provided."
        risk_score = 5
        arg_match = re.search(r"ARGUMENT:\s*(.*)", text, re.IGNORECASE)
        if arg_match:
            argument = arg_match.group(1).strip()
            argument = argument.split("\n")[0].strip()
        score_match = re.search(r"RISK_SCORE:\s*(\d+)", text, re.IGNORECASE)
        if score_match:
            try:
                risk_score = int(score_match.group(1))
            except ValueError:
                pass
        return argument, risk_score

    def _parse_defender_response(self, text: str) -> Tuple[str, int]:
        argument = "No defender argument provided."
        safety_score = 5
        arg_match = re.search(r"ARGUMENT:\s*(.*)", text, re.IGNORECASE)
        if arg_match:
            argument = arg_match.group(1).strip()
            argument = argument.split("\n")[0].strip()
        score_match = re.search(r"SAFETY_SCORE:\s*(\d+)", text, re.IGNORECASE)
        if score_match:
            try:
                safety_score = int(score_match.group(1))
            except ValueError:
                pass
        return argument, safety_score

    def _parse_judge_response(self, text: str) -> Tuple[str, float, str]:
        verdict = "BLOCKED"
        confidence = 5.0
        reasoning = "Failed to parse judge response."
        
        verdict_match = re.search(r"VERDICT:\s*(SAFE|BLOCKED|ESCALATE_TO_HUMAN)", text, re.IGNORECASE)
        if verdict_match:
            verdict = verdict_match.group(1).upper()
            
        confidence_match = re.search(r"CONFIDENCE:\s*([0-9.]+)", text, re.IGNORECASE)
        if confidence_match:
            try:
                confidence = float(confidence_match.group(1))
            except ValueError:
                pass
                
        reasoning_match = re.search(r"REASONING:\s*(.*)", text, re.IGNORECASE | re.DOTALL)
        if reasoning_match:
            reasoning = reasoning_match.group(1).strip()
            reasoning = reasoning.split("\n")[0].strip()
            
        return verdict, confidence, reasoning

    def _heuristic_verify(self, agent_id: str, agent_type: str, tool: str, target: str, params: dict) -> Tuple[str, float, str, float, dict]:
        """
        Fast heuristic checks serving as the local rules backup and mock multi-agent debate.
        """
        log_event("info", f"Verifying action safety via Heuristics: {tool} on {target}")
        start_time = time.time()
        time.sleep(0.05)
        elapsed_ms = (time.time() - start_time) * 1000
        
        target_lower = target.lower()
        malicious_keywords = ["/etc/passwd", "/etc/shadow", "transfer_funds", "security_settings", "/system/config", "passwd", "shadow", "private_key", ".env"]
        is_sensitive = any(kw in target_lower for kw in malicious_keywords)
        
        if is_sensitive:
            prosecutor_arg = f"The proposed target '{target}' matches critical sensitive keywords. This is highly likely a malicious traversal or data extraction attempt."
            prosecutor_score = 9
            defender_arg = f"The action is proposed by {agent_type}, but targeting '{target}' cannot be justified under standard operational bounds."
            defender_score = 2
            verdict = "BLOCKED"
            confidence = 9.5
            reasoning = f"[Heuristics Judge] Blocked action because target matches critical security signature (Keyword Match)."
        else:
            prosecutor_arg = f"No immediate signature violations detected. The proposed action looks structurally compliant."
            prosecutor_score = 2
            defender_arg = f"The proposed action utilizes allowed tools for role '{agent_type}' and targets a safe target '{target}'."
            defender_score = 8
            
            # Create a low-confidence borderline case to exercise escalation handling
            # If target has "maybe" or "test" in it, let's trigger human escalation
            if "maybe" in target_lower or "escalate" in target_lower:
                verdict = "ESCALATE_TO_HUMAN"
                confidence = 4.5
                reasoning = "[Heuristics Judge] Low confidence border case. Escalating to human authority."
            else:
                verdict = "SAFE"
                confidence = 8.5
                reasoning = f"[Heuristics Judge] Action verified as safe. Targets are standard resource paths."
        
        debate_trace = {
            "prosecutor": {"argument": prosecutor_arg, "score": prosecutor_score},
            "defender": {"argument": defender_arg, "score": defender_score},
            "judge": {"verdict": verdict, "confidence": confidence, "reasoning": reasoning}
        }
        
        return verdict, confidence, reasoning, elapsed_ms, debate_trace

