"""
Guardian Swarm Database Models & Persistence Engine
===================================================
Provides SQLAlchemy models for Users, APIKeys, Models, AuditBlock, Conversations, and Messages.
Supports Fernet key encryption and automatic 5-user enterprise seeding.
"""
import os
import time
import json
import base64
from typing import Dict, Any, List, Optional
from pathlib import Path
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, Text, DateTime, ForeignKey, func
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

from guardian_swarm.utils.paths import DATA_DIR

DB_PATH = DATA_DIR / "guardian_swarm.db"
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DB_PATH.as_posix()}")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# =====================================================================
# Encryption Setup (Fernet)
# =====================================================================

ENCRYPTION_KEY_ENV = os.environ.get("ENCRYPTION_KEY")
if ENCRYPTION_KEY_ENV:
    # Ensure key length is valid Fernet key
    try:
        fernet = Fernet(ENCRYPTION_KEY_ENV.encode('utf-8'))
    except Exception:
        # Fallback to key derived from env
        key = base64.urlsafe_b64encode(ENCRYPTION_KEY_ENV.zfill(32)[:32].encode('utf-8'))
        fernet = Fernet(key)
else:
    # Stable default key for local workspace persistence
    default_secret = "GuardianSwarmV3EnterpriseSecretKey32B!"
    key = base64.urlsafe_b64encode(default_secret[:32].encode('utf-8'))
    fernet = Fernet(key)

def encrypt_string(plaintext: str) -> str:
    if not plaintext:
        return ""
    return fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')

def decrypt_string(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return fernet.decrypt(ciphertext.encode('utf-8')).decode('utf-8')
    except Exception:
        return ciphertext

def mask_key(plaintext: str) -> str:
    if not plaintext:
        return ""
    last4 = plaintext[-4:] if len(plaintext) >= 4 else plaintext
    return f"••••••••••••{last4}"


# =====================================================================
# SQLAlchemy Models
# =====================================================================

class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    role = Column(String(20), nullable=False, default="INTERN") # INTERN, EMPLOYEE, MANAGER, EXEC, ADMIN
    department = Column(String(50), nullable=False, default="Engineering")
    password_hash = Column(String(255), nullable=False)
    is_suspended = Column(Boolean, default=False)
    daily_token_limit = Column(Integer, default=10000)
    daily_token_used = Column(Integer, default=0)
    created_at = Column(DateTime, default=func.now())

    conversations = relationship("ConversationModel", back_populates="user", cascade="all, delete-orphan")


class APIKeyModel(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(50), unique=True, index=True, nullable=False) # openai, anthropic, google, etc.
    encrypted_key = Column(Text, nullable=False)
    key_last4 = Column(String(10), nullable=False)
    status = Column(String(20), default="active") # active, expired, disabled
    created_at = Column(DateTime, default=func.now())


class ModelRegistryModel(Base):
    __tablename__ = "model_registry"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    provider = Column(String(50), nullable=False)
    model_type = Column(String(20), default="cloud") # cloud, local
    group_name = Column(String(50), nullable=False) # RESEARCH, CODE, DRAFTING, SUPPORT, DATA_ANALYSIS
    input_cost_per_1m = Column(Float, default=0.0)
    output_cost_per_1m = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)

    # Model File Access & Governance Configuration
    file_access_enabled = Column(Boolean, default=True)
    allowed_categories = Column(Text, default='["Documents","Spreadsheets","Presentations","Code","Archives","Images","Security"]')
    allowed_guardian_tags = Column(Text, default='["PUBLIC","INTERNAL","CONFIDENTIAL"]')
    allowed_groups = Column(Text, default='["RESEARCH","CODE","DRAFTING","SUPPORT","DATA_ANALYSIS"]')
    can_read = Column(Boolean, default=True)
    can_download = Column(Boolean, default=False)
    can_export = Column(Boolean, default=False)


class AuditBlockModel(Base):
    __tablename__ = "audit_blocks"

    id = Column(Integer, primary_key=True, index=True)
    block_index = Column(Integer, unique=True, index=True, nullable=False)
    timestamp = Column(String(50), nullable=False)
    agent_id = Column(String(100), nullable=False)
    action_type = Column(String(50), nullable=False)
    target = Column(String(255), nullable=False)
    verdict = Column(String(20), nullable=False)
    confidence = Column(Float, default=1.0)
    reasoning = Column(Text, nullable=False)
    prev_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False)
    governance_json = Column(Text, nullable=True)


class ConversationModel(Base):
    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, index=True)
    conv_id = Column(String(100), unique=True, index=True, nullable=False)
    user_id = Column(String(50), ForeignKey("users.user_id"), nullable=False)
    title = Column(String(255), nullable=False)
    category = Column(String(50), default="RESEARCH")
    created_at = Column(DateTime, default=func.now())

    user = relationship("UserModel", back_populates="conversations")
    messages = relationship("MessageModel", back_populates="conversation", cascade="all, delete-orphan")


class MessageModel(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    conv_id = Column(String(100), ForeignKey("conversations.conv_id"), nullable=False)
    role = Column(String(20), nullable=False) # user, assistant, system
    content = Column(Text, nullable=False)
    tokens_used = Column(Integer, default=0)
    audit_block_index = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=func.now())

    conversation = relationship("ConversationModel", back_populates="messages")


class FileMindCacheModel(Base):
    __tablename__ = "filemind_cache"

    id = Column(Integer, primary_key=True, index=True)
    path = Column(String(500), unique=True, index=True, nullable=False)
    filemind_category = Column(String(100), nullable=False)
    guardian_classification = Column(String(50), nullable=False)
    file_size = Column(Integer, default=0)
    modified_time = Column(Float, default=0.0)
    content_fingerprint = Column(String(64), nullable=True)
    scanner_version = Column(String(50), default="filemind-0.1")
    scanned_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=False)
    status = Column(String(50), default="classified")
    error_reason = Column(Text, nullable=True)


# =====================================================================
# Database Seeding & Initialization
# =====================================================================

def init_db():
    """Initializes SQLite database and seeds exactly 5 realistic enterprise users once."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)

    # Ensure model_registry table has file access columns if DB existed
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            columns = [row[1] for row in conn.execute(text("PRAGMA table_info(model_registry);")).fetchall()]
            if "file_access_enabled" not in columns:
                conn.execute(text("ALTER TABLE model_registry ADD COLUMN file_access_enabled BOOLEAN DEFAULT 1;"))
                conn.execute(text("ALTER TABLE model_registry ADD COLUMN allowed_categories TEXT DEFAULT '[\"Documents\",\"Spreadsheets\",\"Presentations\",\"Code\",\"Archives\",\"Images\",\"Security\"]';"))
                conn.execute(text("ALTER TABLE model_registry ADD COLUMN allowed_guardian_tags TEXT DEFAULT '[\"PUBLIC\",\"INTERNAL\",\"CONFIDENTIAL\"]';"))
                conn.execute(text("ALTER TABLE model_registry ADD COLUMN allowed_groups TEXT DEFAULT '[\"RESEARCH\",\"CODE\",\"DRAFTING\",\"SUPPORT\",\"DATA_ANALYSIS\"]';"))
                conn.execute(text("ALTER TABLE model_registry ADD COLUMN can_read BOOLEAN DEFAULT 1;"))
                conn.execute(text("ALTER TABLE model_registry ADD COLUMN can_download BOOLEAN DEFAULT 0;"))
                conn.execute(text("ALTER TABLE model_registry ADD COLUMN can_export BOOLEAN DEFAULT 0;"))
                conn.commit()
    except Exception:
        pass

    db = SessionLocal()
    try:
        if db.query(UserModel).count() == 0:
            print("🌱 Seeding database with 5 enterprise users...")
            from werkzeug.security import generate_password_hash

            seed_users = [
                UserModel(
                    user_id="intern_user",
                    name="INTERN",
                    email="intern@enterprise.com",
                    role="INTERN",
                    department="Engineering",
                    password_hash=generate_password_hash("InternPass123!"),
                    is_suspended=False,
                    daily_token_limit=10000,
                    daily_token_used=0
                ),
                UserModel(
                    user_id="employee_user",
                    name="EMPLOYEE",
                    email="employee@enterprise.com",
                    role="EMPLOYEE",
                    department="Engineering",
                    password_hash=generate_password_hash("EmpPass123!"),
                    is_suspended=False,
                    daily_token_limit=25000,
                    daily_token_used=0
                ),
                UserModel(
                    user_id="manager_user",
                    name="MANAGER",
                    email="manager@enterprise.com",
                    role="MANAGER",
                    department="Engineering",
                    password_hash=generate_password_hash("ManagerPass123!"),
                    is_suspended=False,
                    daily_token_limit=50000,
                    daily_token_used=0
                ),
                UserModel(
                    user_id="exec_user",
                    name="EXEC",
                    email="exec@enterprise.com",
                    role="EXEC",
                    department="Leadership",
                    password_hash=generate_password_hash("ExecPass123!"),
                    is_suspended=False,
                    daily_token_limit=200000,
                    daily_token_used=0
                ),
                UserModel(
                    user_id="admin_user",
                    name="ADMIN",
                    email="admin@enterprise.com",
                    role="ADMIN",
                    department="IT Security",
                    password_hash=generate_password_hash("AdminPass123!"),
                    is_suspended=False,
                    daily_token_limit=200000,
                    daily_token_used=0
                )
            ]
            db.add_all(seed_users)

            seed_models = [
                ModelRegistryModel(name="gemini-1.5-pro", provider="google", model_type="cloud", group_name="RESEARCH", input_cost_per_1m=1.25, output_cost_per_1m=5.00, file_access_enabled=True, allowed_guardian_tags='["PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED"]', can_download=True, can_export=True),
                ModelRegistryModel(name="gemini-2.0-flash", provider="google", model_type="cloud", group_name="RESEARCH", input_cost_per_1m=0.10, output_cost_per_1m=0.40, file_access_enabled=True, allowed_guardian_tags='["PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED"]', can_download=True, can_export=True),
                ModelRegistryModel(name="perplexity", provider="perplexity", model_type="cloud", group_name="RESEARCH", input_cost_per_1m=1.00, output_cost_per_1m=3.00, file_access_enabled=True, allowed_guardian_tags='["PUBLIC","INTERNAL","CONFIDENTIAL"]'),
                ModelRegistryModel(name="gpt-4o", provider="openai", model_type="cloud", group_name="RESEARCH", input_cost_per_1m=2.50, output_cost_per_1m=10.00, file_access_enabled=True, allowed_guardian_tags='["PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED"]', can_download=True, can_export=True),
                ModelRegistryModel(name="claude-sonnet-4-6", provider="anthropic", model_type="cloud", group_name="CODE", input_cost_per_1m=3.00, output_cost_per_1m=15.00, file_access_enabled=True, allowed_guardian_tags='["PUBLIC","INTERNAL","CONFIDENTIAL"]'),
                ModelRegistryModel(name="codex", provider="openai", model_type="cloud", group_name="CODE", input_cost_per_1m=3.00, output_cost_per_1m=15.00, file_access_enabled=True, allowed_guardian_tags='["PUBLIC","INTERNAL"]'),
                ModelRegistryModel(name="claude-haiku-4-5", provider="anthropic", model_type="cloud", group_name="DRAFTING", input_cost_per_1m=0.80, output_cost_per_1m=4.00, file_access_enabled=True, allowed_guardian_tags='["PUBLIC","INTERNAL"]'),
                ModelRegistryModel(name="gpt-4o-mini", provider="openai", model_type="cloud", group_name="SUPPORT", input_cost_per_1m=0.15, output_cost_per_1m=0.60, file_access_enabled=True, allowed_guardian_tags='["PUBLIC","INTERNAL"]'),
                ModelRegistryModel(name="phi-3.5-mini", provider="local", model_type="local", group_name="DATA_ANALYSIS", input_cost_per_1m=0.0, output_cost_per_1m=0.0, file_access_enabled=True, allowed_guardian_tags='["PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED"]'),
                ModelRegistryModel(name="smollm2", provider="local", model_type="local", group_name="DATA_ANALYSIS", input_cost_per_1m=0.0, output_cost_per_1m=0.0, file_access_enabled=False),
            ]
            db.add_all(seed_models)

            db.commit()
        else:
            # Migration check: Ensure Gemini models exist in existing DB
            gemini_pro = db.query(ModelRegistryModel).filter(ModelRegistryModel.name == "gemini-1.5-pro").first()
            if not gemini_pro:
                db.add(ModelRegistryModel(name="gemini-1.5-pro", provider="google", model_type="cloud", group_name="RESEARCH", input_cost_per_1m=1.25, output_cost_per_1m=5.00, file_access_enabled=True, allowed_guardian_tags='["PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED"]', can_download=True, can_export=True))
            gemini_flash = db.query(ModelRegistryModel).filter(ModelRegistryModel.name == "gemini-2.0-flash").first()
            if not gemini_flash:
                db.add(ModelRegistryModel(name="gemini-2.0-flash", provider="google", model_type="cloud", group_name="RESEARCH", input_cost_per_1m=0.10, output_cost_per_1m=0.40, file_access_enabled=True, allowed_guardian_tags='["PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED"]', can_download=True, can_export=True))
            db.commit()
            print("[OK] Database initialized with 5 users and model registry.")
    finally:
        db.close()
