"""
Guardian Swarm Enterprise Logging Infrastructure
=================================================
Provides structured JSON logging for all system events, security gate checks,
and audit operations, replacing standard print statements.
"""
import sys
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

class JSONFormatter(logging.Formatter):
    """Custom formatter producing structured JSON log entries."""
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno
        }
        
        # Include extra fields passed to logger
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_obj.update(record.extra_fields)
            
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_obj)

def get_logger(name: str = "guardian_swarm") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.propagate = False
    return logger

def log_event(level: str, message: str, extra: Optional[Dict[str, Any]] = None, logger_name: str = "guardian_swarm"):
    logger = get_logger(logger_name)
    extra_dict = {"extra_fields": extra} if extra else {}
    log_func = getattr(logger, level.lower(), logger.info)
    log_func(message, extra=extra_dict)
