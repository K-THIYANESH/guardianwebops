import uuid
import datetime
from typing import List, Dict, Any

class EscalationQueue:
    """
    In-memory queue for tracking and resolving actions escalated for human review.
    """
    def __init__(self):
        self.queue: List[Dict[str, Any]] = []

    def add(self, action: dict, prosecutor_output: dict, defender_output: dict, judge_output: dict, timestamp: str = None) -> dict:
        if not timestamp:
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        item = {
            "id": action.get("action_id") or str(uuid.uuid4()),
            "timestamp": timestamp,
            "agent_id": action.get("agent_id", "unknown"),
            "agent_type": action.get("agent_type", "unknown"),
            "tool": action.get("tool", "unknown"),
            "target": action.get("target", "unknown"),
            "params": action.get("params", {}),
            "debate_trace": {
                "prosecutor": prosecutor_output,
                "defender": defender_output,
                "judge": judge_output
            },
            "status": "pending",
            "decision": None
        }
        self.queue.append(item)
        return item

    def get_pending(self) -> List[Dict[str, Any]]:
        return [item for item in self.queue if item["status"] == "pending"]

    def list_pending(self) -> List[Dict[str, Any]]:
        """Alias for get_pending()."""
        return self.get_pending()

    def resolve(self, escalation_id: str, human_decision: str) -> bool:
        for item in self.queue:
            if item["id"] == escalation_id:
                item["status"] = "resolved"
                item["decision"] = human_decision
                return True
        return False
