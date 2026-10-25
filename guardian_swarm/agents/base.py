from typing import Tuple

class SpecialistAgent:
    """
    Base class representing a specialist agent in the Guardian runtime.
    Includes support for simulating prompt injection via poison().
    """
    def __init__(self, agent_id: str, agent_type: str):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.poisoned = False

    def poison(self):
        """
        Simulates prompt injection causing the agent to attempt malicious actions.
        """
        self.poisoned = True

    def propose_action(self, task_description: str) -> Tuple[str, str, dict]:
        """
        Subclasses override this to propose actions based on normal task descriptions
        or malicious prompt injection payloads.
        """
        raise NotImplementedError("Subclasses must implement propose_action")
