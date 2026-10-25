from typing import Dict, Any, Optional
from guardian_swarm.core.exceptions import (
    UserWalletExhaustedException,
    TeamPoolExhaustedException,
    OrgCeilingExceededException,
    PreFlightCostExceedsBudgetException
)
from guardian_swarm.utils.database import SessionLocal, UserModel, ModelRegistryModel

MODEL_COSTS = {
    # input cost & output cost per 1M tokens in USD
    "gpt-4o":           {"input": 2.50,  "output": 10.00},
    "gpt-4o-mini":      {"input": 0.15,  "output": 0.60},
    "claude-sonnet-4-6":{"input": 3.00,  "output": 15.00},
    "claude-haiku-4-5": {"input": 0.80,  "output": 4.00},
    "codex":            {"input": 3.00,  "output": 15.00},
    "perplexity":       {"input": 1.00,  "output": 3.00},
    "phi-3.5-mini":     {"input": 0.00,  "output": 0.00},
    "smollm2":          {"input": 0.00,  "output": 0.00},
    "heuristic":        {"input": 0.00,  "output": 0.00}
}

DEFAULT_BUDGETS = {
    "INTERN":   {"daily_tokens": 10000},
    "EMPLOYEE": {"daily_tokens": 25000},
    "MANAGER":  {"daily_tokens": 50000},
    "EXEC":     {"daily_tokens": 200000},
    "ADMIN":    {"daily_tokens": 200000}
}

class BudgetGate:
    """
    Gate 4: Budget Gate.
    Calculates token counts using tiktoken, queries costs, and enforces per-user wallets,
    team pools, and organization caps with hard stops BEFORE overage.
    """
    def __init__(self):
        self.team_pools: Dict[str, Dict[str, Any]] = {
            "engineering": {"monthly_tokens": 500000, "used_this_month": 127420},
            "research":    {"monthly_tokens": 300000, "used_this_month": 44200},
            "leadership":  {"monthly_tokens": 200000, "used_this_month": 18900},
            "it security":  {"monthly_tokens": 500000, "used_this_month": 10000}
        }
        self.org_ceiling = {
            "monthly_tokens": 5000000,
            "used_this_month": 190520,
            "alert_threshold_pct": 80,
            "exec_override_allowed": True
        }

    def estimate_tokens(self, prompt: str) -> int:
        """Estimate tokens using tiktoken cl100k_base encoder."""
        if not prompt:
            return 10
        try:
            import tiktoken
            encoding = tiktoken.get_encoding("cl100k_base")
            return max(10, len(encoding.encode(prompt)))
        except Exception:
            return max(10, len(prompt) // 4)

    def estimate_cost_usd(self, tokens: int, model: str) -> float:
        """Calculates cost USD using database model costs or MODEL_COSTS lookup."""
        model_key = model.lower()
        rates = None

        db = SessionLocal()
        try:
            reg = db.query(ModelRegistryModel).filter(ModelRegistryModel.name == model_key).first()
            if reg:
                rates = {"input": reg.input_cost_per_1m, "output": reg.output_cost_per_1m}
        except Exception:
            pass
        finally:
            db.close()

        if not rates:
            rates = MODEL_COSTS.get(model_key)
            if not rates:
                for k, v in MODEL_COSTS.items():
                    if k in model_key or model_key in k:
                        rates = v
                        break
        if not rates:
            rates = {"input": 1.00, "output": 3.00}

        avg_rate = (rates["input"] + rates["output"]) / 2.0
        return round((tokens / 1_000_000.0) * avg_rate, 6)

    def get_user_wallet_db(self, user_id: str, role: str) -> Dict[str, Any]:
        """Fetch user token limit and usage from DB."""
        db = SessionLocal()
        try:
            usr = db.query(UserModel).filter(UserModel.user_id == user_id).first()
            if usr:
                return {"used": usr.daily_token_used, "limit": usr.daily_token_limit}
        except Exception:
            pass
        finally:
            db.close()

        role_upper = role.upper()
        limit = DEFAULT_BUDGETS.get(role_upper, {"daily_tokens": 10000})["daily_tokens"]
        return {"used": 0, "limit": limit}

    def deduct_user_tokens(self, user_id: str, tokens: int):
        """Update user token count in DB upon execution."""
        db = SessionLocal()
        try:
            usr = db.query(UserModel).filter(UserModel.user_id == user_id).first()
            if usr:
                usr.daily_token_used += tokens
                db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    def preflight(self, session: Any, model: str, prompt: str) -> Dict[str, Any]:
        """
        Pre-flight token and budget evaluation.
        Hard stops BEFORE overage occurred by raising BGE_001, BGE_002, BGE_003, or BGE_004.
        """
        user_id = getattr(session, "user_id", "intern_user")
        role = getattr(session, "role", "INTERN").upper()
        team_id = getattr(session, "department", getattr(session, "team_id", "engineering")).lower()

        tokens_est = self.estimate_tokens(prompt)
        cost_usd = self.estimate_cost_usd(tokens_est, model)

        wallet = self.get_user_wallet_db(user_id, role)
        wallet_remaining = wallet["limit"] - wallet["used"]
        can_override = (role in ["EXEC", "ADMIN"])

        # 1. User Wallet Exhausted Check
        if (wallet_remaining <= 0 or wallet["used"] + tokens_est > wallet["limit"]) and not can_override:
            raise UserWalletExhaustedException(
                user_id=user_id,
                used=wallet["used"],
                limit=wallet["limit"],
                reason=f"User daily token wallet exhausted ({wallet['used']}/{wallet['limit']} tokens)."
            )

        # 2. Team Pool Check
        team = self.team_pools.get(team_id, {"monthly_tokens": 500000, "used_this_month": 0})
        team_remaining = team["monthly_tokens"] - team["used_this_month"]
        if (team_remaining <= 0 or team["used_this_month"] + tokens_est > team["monthly_tokens"]) and not can_override:
            raise TeamPoolExhaustedException(
                team_id=team_id,
                used=team["used_this_month"],
                limit=team["monthly_tokens"],
                reason=f"Team monthly budget pool for '{team_id}' at ceiling ({team['used_this_month']}/{team['monthly_tokens']} tokens)."
            )

        # 3. Org Ceiling Check
        org_remaining = self.org_ceiling["monthly_tokens"] - self.org_ceiling["used_this_month"]
        if (org_remaining <= 0 or self.org_ceiling["used_this_month"] + tokens_est > self.org_ceiling["monthly_tokens"]) and not can_override:
            raise OrgCeilingExceededException(
                org_id="enterprise_org",
                used=self.org_ceiling["used_this_month"],
                limit=self.org_ceiling["monthly_tokens"],
                reason=f"Organization monthly hard token ceiling exceeded."
            )

        # 4. Preflight Cost Check vs Wallet Balance
        if tokens_est > wallet_remaining and not can_override:
            raise PreFlightCostExceedsBudgetException(
                estimated_cost=tokens_est,
                remaining_budget=wallet_remaining,
                reason=f"Estimated tokens ({tokens_est}) exceeds user remaining budget ({wallet_remaining})."
            )

        return {
            "tokens_est": tokens_est,
            "cost_usd": cost_usd,
            "user_remaining": wallet_remaining - tokens_est,
            "team_remaining": team_remaining - tokens_est
        }
