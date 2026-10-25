from dataclasses import dataclass
from typing import Dict, List, Set, Any, Optional
from guardian_swarm.utils.database import SessionLocal, UserModel
from guardian_swarm.core.exceptions import (
    RoleNotPermittedForTaskException,
    DataClassificationExceededException,
    SubagentSpawnDeniedException,
    UserSuspendedException,
    RolePermissionNotFoundException
)

DATA_CLASSIFICATIONS = ["PUBLIC", "INTERNAL", "SENSITIVE", "RESTRICTED"]

ROLE_LEVELS: Dict[str, int] = {
    "INTERN": 10,
    "EMPLOYEE": 20,
    "MANAGER": 30,
    "EXEC": 40,
    "ADMIN": 50,
}

def get_role_level(role: str) -> int:
    """Returns integer rank level for given role (0 if unknown)."""
    if not role or not isinstance(role, str):
        return 0
    return ROLE_LEVELS.get(role.upper().strip(), 0)

def has_minimum_role(user_role: str, required_role: str) -> bool:
    """
    Checks if user_role level is greater than or equal to required_role level.
    ADMIN (50) >= EXEC (40) >= MANAGER (30) >= EMPLOYEE (20) >= INTERN (10)
    """
    return get_role_level(user_role) >= get_role_level(required_role)

def has_exact_role(user_role: str, required_role: str) -> bool:
    """Checks if user_role matches required_role exactly (case-insensitive)."""
    if not user_role or not required_role:
        return False
    return user_role.upper().strip() == required_role.upper().strip()

def require_minimum_role(user_role: str, required_role: str) -> bool:
    """
    Enforces minimum role level. Raises RoleNotPermittedForTaskException if check fails.
    """
    if not has_minimum_role(user_role, required_role):
        raise RoleNotPermittedForTaskException(
            user_id="auth_check",
            role=user_role,
            category=f"MINIMUM_ROLE_{required_role.upper()}",
            details={
                "required_role": required_role.upper(),
                "current_role": (user_role or "").upper(),
                "required_level": get_role_level(required_role),
                "current_level": get_role_level(user_role)
            }
        )
    return True

def require_exact_role(user_role: str, required_role: str) -> bool:
    """
    Enforces exact role match. Raises RoleNotPermittedForTaskException if check fails.
    """
    if not has_exact_role(user_role, required_role):
        raise RoleNotPermittedForTaskException(
            user_id="auth_check",
            role=user_role,
            category=f"EXACT_ROLE_{required_role.upper()}",
            details={
                "required_role": required_role.upper(),
                "current_role": (user_role or "").upper()
            }
        )
    return True

ROLE_MATRIX: Dict[str, Dict[str, Any]] = {
    "INTERN": {
        "allowed_categories": ["DRAFTING", "SUPPORT"],
        "max_data_classification": "INTERNAL",
        "can_spawn_subagents": False
    },
    "EMPLOYEE": {
        "allowed_categories": ["RESEARCH", "CODE", "DRAFTING", "SUPPORT", "DATA_ANALYSIS"],
        "max_data_classification": "INTERNAL",
        "can_spawn_subagents": False
    },
    "MANAGER": {
        "allowed_categories": ["RESEARCH", "CODE", "DRAFTING", "SUPPORT", "DATA_ANALYSIS"],
        "max_data_classification": "SENSITIVE",
        "can_spawn_subagents": True
    },
    "EXEC": {
        "allowed_categories": ["RESEARCH", "CODE", "DRAFTING", "SUPPORT", "DATA_ANALYSIS"],
        "max_data_classification": "RESTRICTED",
        "can_spawn_subagents": True
    },
    "ADMIN": {
        "allowed_categories": ["RESEARCH", "CODE", "DRAFTING", "SUPPORT", "DATA_ANALYSIS"],
        "max_data_classification": "RESTRICTED",
        "can_spawn_subagents": True
    }
}

@dataclass
class UserSession:
    user_id: str
    role: str
    department: str = "Engineering"
    name: str = "User"
    email: str = ""
    is_suspended: bool = False

    @property
    def team_id(self) -> str:
        return self.department.lower()


class UserRBACGate:
    """
    Gate 1: User RBAC Gate.
    Queries database for user verification & checks session against ROLE_MATRIX.
    Verifies user suspension, task categories, data classifications, and subagent spawning.
    """
    def __init__(self, matrix: Optional[Dict[str, Dict[str, Any]]] = None):
        self.matrix = matrix or ROLE_MATRIX

    def get_db_user(self, user_id: str) -> Optional[UserModel]:
        db = SessionLocal()
        try:
            return db.query(UserModel).filter(UserModel.user_id == user_id).first()
        finally:
            db.close()

    def check(
        self,
        session: UserSession,
        task_category: str,
        data_classification: str = "PUBLIC",
        spawn_subagent: bool = False
    ) -> bool:
        user_id = session.user_id
        
        # 1. Database user query & status check
        db_user = self.get_db_user(user_id)
        if db_user:
            if db_user.is_suspended:
                raise UserSuspendedException(
                    user_id=user_id,
                    reason=f"User account '{user_id}' is marked as suspended in the database."
                )
            role = db_user.role.upper()
        else:
            if session.is_suspended:
                raise UserSuspendedException(
                    user_id=user_id,
                    reason=f"User session '{user_id}' is suspended."
                )
            role = (session.role or "INTERN").upper()

        if role not in self.matrix:
            raise RolePermissionNotFoundException(
                user_id=user_id,
                role=role,
                reason=f"Role '{role}' does not exist in RBAC permission matrix."
            )

        perms = self.matrix[role]

        # 2. Check Task Category Authorization
        cat_upper = (task_category or "RESEARCH").upper()
        allowed_cats = perms.get("allowed_categories", [])
        if cat_upper not in allowed_cats:
            raise RoleNotPermittedForTaskException(
                user_id=user_id,
                role=role,
                category=cat_upper,
                details={"permitted_groups": allowed_cats}
            )

        # 3. Check Data Classification Authorization
        class_upper = (data_classification or "PUBLIC").upper()
        max_class = perms.get("max_data_classification", "INTERNAL").upper()

        req_idx = DATA_CLASSIFICATIONS.index(class_upper) if class_upper in DATA_CLASSIFICATIONS else 0
        max_idx = DATA_CLASSIFICATIONS.index(max_class) if max_class in DATA_CLASSIFICATIONS else 1

        if req_idx > max_idx:
            raise DataClassificationExceededException(
                user_id=user_id,
                role=role,
                classification=class_upper,
                max_allowed=max_class
            )

        # 4. Check Subagent Spawning Authorization
        if spawn_subagent and not perms.get("can_spawn_subagents", False):
            raise SubagentSpawnDeniedException(
                user_id=user_id,
                role=role
            )

        return True
