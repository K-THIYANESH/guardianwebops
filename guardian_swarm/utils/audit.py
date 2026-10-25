import hashlib
import json
import uuid
import datetime
from typing import List, Dict, Any, Tuple
from guardian_swarm.utils.database import SessionLocal, AuditBlockModel

class AuditLog:
    """
    Cryptographically chained log system with SHA-256 integrity.
    Persists blocks to SQLite database.
    """
    def __init__(self):
        self.chain: List[Dict[str, Any]] = []
        self._load_from_db()

    def _load_from_db(self):
        db = SessionLocal()
        try:
            blocks = db.query(AuditBlockModel).order_by(AuditBlockModel.block_index.asc()).all()
            self.chain = []
            for b in blocks:
                gov = json.loads(b.governance_json) if b.governance_json else {}
                entry = {
                    "timestamp": b.timestamp,
                    "action_id": gov.get("action_id", f"block_{b.block_index}"),
                    "agent_id": b.agent_id,
                    "governance": gov.get("governance", {}),
                    "proposed_action": {
                        "agent_type": b.action_type,
                        "tool": gov.get("tool", "action"),
                        "target": b.target,
                        "params": gov.get("params", {})
                    },
                    "verdict": b.verdict,
                    "reasoning": b.reasoning,
                    "confidence": b.confidence,
                    "investigation_trace": gov.get("trace", []),
                    "prev_hash": b.prev_hash,
                    "entry_hash": b.entry_hash
                }
                if "debate_trace" in gov:
                    entry["debate_trace"] = gov["debate_trace"]
                self.chain.append(entry)
        except Exception:
            pass
        finally:
            db.close()

    def create_entry(
        self,
        agent_id: str,
        agent_type: str,
        tool: str,
        target: str,
        params: dict,
        verdict: str,
        confidence: float,
        reasoning: str,
        trace: List[str],
        debate_trace: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        action_id = f"block_{len(self.chain)}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        prev_hash = "0" * 64
        if self.chain:
            prev_hash = self.chain[-1]["entry_hash"]

        entry_data = {
            "timestamp": timestamp,
            "action_id": action_id,
            "agent_id": agent_id,
            "governance": params.get("governance", {}) if isinstance(params, dict) else {},
            "proposed_action": {
                "agent_type": agent_type,
                "tool": tool,
                "target": target,
                "params": params
            },
            "verdict": verdict,
            "reasoning": reasoning,
            "confidence": confidence,
            "investigation_trace": trace,
            "prev_hash": prev_hash
        }
        if debate_trace:
            entry_data["debate_trace"] = debate_trace

        entry_json = json.dumps(entry_data, sort_keys=True)
        entry_hash = hashlib.sha256(entry_json.encode('utf-8')).hexdigest()
        entry_data["entry_hash"] = entry_hash

        self.chain.append(entry_data)

        # Persist to SQLite AuditBlockModel
        db = SessionLocal()
        try:
            gov_payload = {
                "action_id": action_id,
                "tool": tool,
                "params": params,
                "trace": trace,
                "governance": entry_data["governance"]
            }
            if debate_trace:
                gov_payload["debate_trace"] = debate_trace

            block_record = AuditBlockModel(
                block_index=len(self.chain) - 1,
                timestamp=timestamp,
                agent_id=agent_id,
                action_type=agent_type,
                target=target,
                verdict=verdict,
                confidence=confidence,
                reasoning=reasoning,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
                governance_json=json.dumps(gov_payload)
            )
            db.add(block_record)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

        return entry_data

    def resolve_entry(self, action_id: str, approved: bool) -> Dict[str, Any]:
        found_idx = -1
        for i, block in enumerate(self.chain):
            if block.get("action_id") == action_id or f"block_{i}" == action_id:
                block["verdict"] = "SAFE" if approved else "BLOCKED"
                block["human_resolved"] = True
                found_idx = i
                break

        if found_idx != -1:
            for i in range(found_idx, len(self.chain)):
                if i == 0:
                    self.chain[i]["prev_hash"] = "0" * 64
                else:
                    self.chain[i]["prev_hash"] = self.chain[i-1]["entry_hash"]

                temp_block = dict(self.chain[i])
                temp_block.pop("entry_hash", None)
                entry_json = json.dumps(temp_block, sort_keys=True)
                self.chain[i]["entry_hash"] = hashlib.sha256(entry_json.encode('utf-8')).hexdigest()

            return self.chain[found_idx]
        return None

    def verify_chain(self) -> Tuple[bool, str]:
        for i, entry in enumerate(self.chain):
            entry_copy = entry.copy()
            if "entry_hash" not in entry_copy:
                return False, f"Missing block hash at index {i}."

            entry_hash = entry_copy.pop("entry_hash")
            entry_json = json.dumps(entry_copy, sort_keys=True)
            recomputed = hashlib.sha256(entry_json.encode('utf-8')).hexdigest()

            if recomputed != entry_hash:
                return False, f"Hash mismatch at Block {i}. Data has been tampered with."

            if i > 0:
                expected_prev_hash = self.chain[i-1]["entry_hash"]
                if entry["prev_hash"] != expected_prev_hash:
                    return False, f"Broken chain link at Block {i}. Expected prev hash: {expected_prev_hash}, Found: {entry['prev_hash']}"

        return True, "Chain integrity verified. All logs are valid and un-tampered."

    def verify_chain_raise(self) -> None:
        from guardian_swarm.core.exceptions import LedgerVerificationException
        import re
        valid, msg = self.verify_chain()
        if not valid:
            match = re.search(r"Block (\d+)", msg)
            idx = int(match.group(1)) if match else 0
            raise LedgerVerificationException(idx, msg)

    def verify_integrity(self) -> Tuple[bool, int, str]:
        valid, msg = self.verify_chain()
        return valid, len(self.chain), msg
