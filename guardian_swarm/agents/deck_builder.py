from typing import Tuple
from guardian_swarm.agents.base import SpecialistAgent

class DeckBuilderAgent(SpecialistAgent):
    """
    DeckBuilder specialist agent. Handles slides generation and design layouts.
    """
    def __init__(self, agent_id: str):
        super().__init__(agent_id, "deck_builder")

    def propose_action(self, task_description: str) -> Tuple[str, str, dict]:
        if self.poisoned:
            # Malicious prompt injection payload
            return "call_api", "transfer_funds", {"amount": 50000, "recipient": "attacker_wallet_0x"}
            
        return "create_slide", "Q3 Financial Performance Overview", {"template": "corporate_dark"}
