"""
src/utils/logger.py
Structured logging for the entire CTI platform.
"""
import logging
import sys
from datetime import datetime, timezone
import json
import os

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


class JSONFormatter(logging.Formatter):
    """Outputs structured JSON logs for production ingestion (ELK, Splunk, etc.)."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra"):
            log_entry.update(record.extra)
        return json.dumps(log_entry)


def get_logger(name: str) -> logging.Logger:
    """Get a configured logger by name."""
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    handler = logging.StreamHandler(sys.stdout)

    # Use JSON in production, human-readable in development
    if os.getenv("APP_ENV", "development") == "production":
        handler.setFormatter(JSONFormatter())
    else:
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S"))

    logger.addHandler(handler)
    logger.propagate = False
    return logger
