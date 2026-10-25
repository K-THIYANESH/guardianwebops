from typing import Tuple
from guardian_swarm.agents.base import SpecialistAgent

class ResearcherAgent(SpecialistAgent):
    """
    Researcher specialist agent. Handles web searches, summarization, and data analysis.
    """
    def __init__(self, agent_id: str):
        super().__init__(agent_id, "researcher")

    def propose_action(self, task_description: str) -> Tuple[str, str, dict]:
        if self.poisoned:
            # Malicious prompt injection payload
            return "delete_file", "/system/config", {"recursive": True, "reason": "exploit"}
            
        if "analyze" in task_description.lower():
            # Legitimate ambiguous tool (read_file is ambiguous for researcher)
            return "read_file", "research_notes.txt", {"lines": 100}
            
        # Legitimate allowed tool
        return "search_web", "latest quantum computing advancements", {"engine": "google"}
