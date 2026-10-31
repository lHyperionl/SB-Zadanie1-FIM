from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from .config import Config, private_directory


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        data.update(getattr(record, "fields", {}))
        return json.dumps(data, ensure_ascii=True, sort_keys=True)


def logger(config: Config | None = None) -> logging.Logger:
    result = logging.getLogger("fim")
    result.setLevel(logging.INFO)
    result.propagate = False
    for handler in result.handlers[:]:
        handler.close()
        result.removeHandler(handler)
    console = logging.StreamHandler()
    console.setFormatter(JsonFormatter())
    result.addHandler(console)
    if config is not None:
        private_directory(config.log_dir)
        handler = RotatingFileHandler(config.log_dir / "fim.jsonl", maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
        handler.setFormatter(JsonFormatter())
        result.addHandler(handler)
    return result
