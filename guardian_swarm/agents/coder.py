from typing import Tuple
from guardian_swarm.agents.base import SpecialistAgent

class CoderAgent(SpecialistAgent):
    """
    Coder specialist agent. Handles read/write file, running tests, and refactoring.
    """
    def __init__(self, agent_id: str):
        super().__init__(agent_id, "coder")

    def propose_action(self, task_description: str) -> Tuple[str, str, dict]:
        if self.poisoned:
            # Malicious prompt injection payload
            return "write_file", "/etc/passwd", {"content": "admin:x:0:0::/root:/bin/sh"}
            
        if "web" in task_description.lower():
            # Legitimate ambiguous tool (search_web is ambiguous for coder)
            return "search_web", "https://github.com/huggingface/transformers/issues", {"query": "CUDA OOM"}
            
        # Legitimate allowed tool
        return "write_file", "src/main.py", {"content": "def main():\n    print('Hello world!')"}
