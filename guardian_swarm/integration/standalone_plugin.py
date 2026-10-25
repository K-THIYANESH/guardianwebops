"""
Standalone Guardian Plugin
==========================
Wraps specialist agents with Guardian Swarm's verification layer so the
application can run independently without any OpenSwarm-specific integration.
"""

from typing import Any, Callable, Dict
import functools

from guardian_swarm.core.exceptions import (
    AISafetyViolationException,
    GuardianSecurityException,
    HighRiskTargetException,
    HumanEscalationRequiredException,
    PolicyViolationException,
)
from guardian_swarm.core.interceptor import GuardianInterceptor
from guardian_swarm.core.policies import is_forbidden_tool, is_high_risk_target


class StandaloneGuardPlugin:
    """Wraps agents or tools and enforces the Guardian guardrail checks."""

    def __init__(self, interceptor: GuardianInterceptor):
        self.interceptor = interceptor

    def _raise_security_exception(self, agent_id: str, agent_type: str, tool: str, target: str, log: Dict[str, Any]):
        reason = log.get("reasoning", "Blocked by security policy.")
        verdict = log.get("verdict", "")
        if verdict == "ESCALATE_TO_HUMAN":
            raise HumanEscalationRequiredException(agent_id=agent_id, agent_type=agent_type, tool=tool, target=target, reason=reason)
        if is_forbidden_tool(agent_type, tool):
            raise PolicyViolationException(agent_id=agent_id, agent_type=agent_type, tool=tool, target=target, reason=reason)
        if is_high_risk_target(target):
            raise HighRiskTargetException(agent_id=agent_id, agent_type=agent_type, tool=tool, target=target, reason=reason)
        raise AISafetyViolationException(agent_id=agent_id, agent_type=agent_type, tool=tool, target=target, reason=reason)

    def secure_tool(self, agent_type: str, agent_id: str):
        def decorator(func: Callable):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                tool = func.__name__
                target = "unknown"
                if args:
                    target = str(args[0])
                elif "target" in kwargs:
                    target = str(kwargs["target"])
                elif "path" in kwargs:
                    target = str(kwargs["path"])
                elif "filename" in kwargs:
                    target = str(kwargs["filename"])

                approved, log = self.interceptor.intercept_action(
                    agent_id=agent_id,
                    agent_type=agent_type,
                    tool=tool,
                    target=target,
                    params=kwargs,
                )
                if not approved:
                    self._raise_security_exception(agent_id, agent_type, tool, target, log)
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def secure_agent(self, agent_instance: Any):
        original_propose = getattr(agent_instance, "propose_action", None)
        if not original_propose:
            raise AttributeError("Agent instance must have a 'propose_action' method.")

        @functools.wraps(original_propose)
        def wrapped_propose(*args, **kwargs):
            tool, target, params = original_propose(*args, **kwargs)
            approved, log = self.interceptor.intercept_action(
                agent_id=agent_instance.agent_id,
                agent_type=agent_instance.agent_type,
                tool=tool,
                target=target,
                params=params,
            )
            if not approved:
                self._raise_security_exception(agent_instance.agent_id, agent_instance.agent_type, tool, target, log)
            return tool, target, params

        agent_instance.propose_action = wrapped_propose
        return agent_instance
