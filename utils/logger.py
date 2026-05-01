"""
Logger utility — file + console logging with credential masking.
"""

import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path


_MASK_PATTERNS = [
    (re.compile(r'(password["\s:=]+)[^\s\'"&,;]+', re.IGNORECASE), r'\1****'),
    (re.compile(r'(passwd["\s:=]+)[^\s\'"&,;]+', re.IGNORECASE), r'\1****'),
    (re.compile(r'(secret["\s:=]+)[^\s\'"&,;]+', re.IGNORECASE), r'\1****'),
    (re.compile(r'(api[_-]?key["\s:=]+)[^\s\'"&,;]+', re.IGNORECASE), r'\1****'),
    (re.compile(r'(token["\s:=]+)[^\s\'"&,;]+', re.IGNORECASE), r'\1****'),
    (re.compile(r'(hash["\s:=]+)[a-fA-F0-9]{16,}', re.IGNORECASE), r'\1****'),
    (re.compile(r'(sk-ant-[a-zA-Z0-9\-]+)', re.IGNORECASE), r'sk-ant-****'),
    # NTLM / LM hashes (32 hex chars)
    (re.compile(r'\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b'), '****:****'),
]


def _mask(message: str) -> str:
    for pattern, replacement in _MASK_PATTERNS:
        message = pattern.sub(replacement, message)
    return message


class MaskingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        record.msg = _mask(str(record.msg))
        if record.args:
            try:
                record.args = tuple(_mask(str(a)) for a in record.args)
            except Exception:
                pass
        return super().format(record)


def get_logger(name: str = "ai_attack_orchestrator", log_dir: str = "logs") -> logging.Logger:
    """Return a configured logger that writes to file and optionally to console."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # Ensure log directory exists
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"engagement_{timestamp}.log")

    fmt = MaskingFormatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler — DEBUG and above
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


# Module-level default logger
log = get_logger()
