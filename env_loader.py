"""Small .env loader for Honeypotv2.03.

This avoids requiring python-dotenv while still allowing setup.py to create a
local .env file that the app can consume. Existing process environment values
win by default so Docker/systemd/Kubernetes secrets are not overwritten.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Iterable, Union


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def parse_env_lines(lines: Iterable[str]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        parsed[key] = _strip_quotes(value)
    return parsed


def load_env_file(path: Union[str, Path] = ".env", override: bool = False) -> Dict[str, str]:
    env_path = Path(path)
    if not env_path.is_absolute():
        env_path = Path(__file__).resolve().parent / env_path
    if not env_path.exists():
        return {}

    parsed = parse_env_lines(env_path.read_text().splitlines())
    for key, value in parsed.items():
        if override or key not in os.environ:
            os.environ[key] = value
    return parsed
