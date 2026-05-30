"""HoneyPot v3.1 performance, deception, and analysis helpers.

All helpers are defensive and designed for owned/authorized honeypot deployments.
They are intentionally dependency-light so sensors can use them without slowing
connection handling.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import random
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterable, Any

COLLABORATOR_RE = re.compile(
    r"(?P<domain>(?:[a-z0-9-]+\.)+(?P<provider>burpcollaborator\.net|oastify\.com))",
    re.IGNORECASE,
)

DECOY_SWAGGER = {
    "openapi": "3.0.3",
    "info": {"title": "Acme Customer Portal API", "version": "2.7.4"},
    "paths": {
        "/api/v1/customers": {"get": {"summary": "List customer records"}},
        "/api/v1/invoices": {"get": {"summary": "List invoice records"}},
        "/api/v1/auth/refresh": {"post": {"summary": "Refresh portal session"}},
        "/api/v1/admin/reports": {"get": {"summary": "Export operational reports"}},
    },
}

FAKE_STACK_TRACES = {
    404: "Symfony\\Component\\HttpKernel\\Exception\\NotFoundHttpException: No route found for GET {path}",
    500: "Illuminate\\Database\\QueryException: SQLSTATE[HY000] [2002] Connection refused",
    403: "django.core.exceptions.PermissionDenied: CSRF verification failed. Request aborted.",
}


class ThreadedTaskQueue:
    """Small wrapper around ThreadPoolExecutor for non-blocking analysis work."""

    def __init__(self, max_workers: int = 4):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="hpv31")

    def submit(self, fn: Callable[..., Any], *args, **kwargs):
        return self.executor.submit(fn, *args, **kwargs)

    def shutdown(self, wait: bool = False):
        self.executor.shutdown(wait=wait, cancel_futures=not wait)


class EventWriteBuffer:
    """Thread-safe in-memory event buffer flushed to a supplied sink in batches."""

    def __init__(self, flush_interval: float = 0.5, sink: Callable[[list[dict]], Any] | None = None):
        self.flush_interval = flush_interval
        self.sink = sink or (lambda batch: None)
        self._events: list[dict] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    def add(self, event: dict):
        with self._lock:
            self._events.append(dict(event))

    def pending_count(self) -> int:
        with self._lock:
            return len(self._events)

    def flush(self) -> int:
        with self._lock:
            batch = self._events
            self._events = []
        if not batch:
            return 0
        try:
            self.sink(batch)
        except Exception:
            with self._lock:
                self._events = batch + self._events
            raise
        return len(batch)

    def start(self):
        if self._running:
            return
        self._running = True

        def loop():
            while self._running:
                time.sleep(self.flush_interval)
                try:
                    self.flush()
                except Exception:
                    # Preserve the batch for the next flush attempt; callers can still
                    # surface explicit flush failures during shutdown/tests.
                    continue

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=self.flush_interval * 2)
        self.flush()


class LazyClassifier:
    """Runs command classification after session activity is available."""

    def __init__(self, predict_fn: Callable[[str], str | None], max_workers: int = 2):
        self.queue = ThreadedTaskQueue(max_workers=max_workers)
        self.predict_fn = predict_fn

    def classify_session_async(self, session_id: int, commands: Iterable[str]):
        return self.queue.submit(self._classify, session_id, list(commands))

    def _classify(self, session_id: int, commands: list[str]) -> dict:
        joined = "\n".join(commands)
        category = self.predict_fn(joined) or "Unknown"
        return {"session_id": session_id, "attack_category": category}

    def shutdown(self):
        self.queue.shutdown(wait=True)


def should_run_heavy_analysis(session_duration_sec: float, minimum_seconds: float = 60) -> bool:
    return float(session_duration_sec or 0) > minimum_seconds


def detect_collaborator_payload(payload: str | bytes | None) -> dict | None:
    if payload is None:
        return None
    text = payload.decode("utf-8", errors="ignore") if isinstance(payload, bytes) else str(payload)
    match = COLLABORATOR_RE.search(text)
    if not match:
        return None
    return {"domain": match.group("domain").lower(), "provider": match.group("provider").lower().split(".")[0]}


def noise_intent_score(commands: Iterable[str], session_duration_sec: float = 0, services: Iterable[str] | None = None,
                       inter_command_delays: Iterable[float] | None = None) -> float:
    commands = [str(c).strip() for c in commands if str(c).strip()]
    services = set(services or [])
    delays = list(inter_command_delays or [])
    if not commands:
        return 0.0

    unique_ratio = len(set(commands)) / max(len(commands), 1)
    duration_score = min(float(session_duration_sec or 0) / 180.0, 1.0)
    service_score = min(len(services) / 3.0, 1.0)
    delay_score = 0.0
    if delays:
        humanish = [d for d in delays if 1.0 <= d <= 30.0]
        delay_score = len(humanish) / len(delays)
    shell_markers = ("sudo", "whoami", "id", "find ", "cat ", "curl", "wget", "python", "perl", "bash", "chmod")
    command_depth = sum(1 for c in commands if any(m in c.lower() for m in shell_markers)) / len(commands)

    score = (unique_ratio * 0.20) + (duration_score * 0.30) + (service_score * 0.15) + (delay_score * 0.15) + (command_depth * 0.20)
    return round(max(0.0, min(score, 1.0)), 3)


def classify_intent(score: float, threshold: float = 0.6) -> str:
    return "human" if score >= threshold else "scanner"


@dataclass
class SessionReplay:
    width: int = 80
    height: int = 24
    events: list[list[Any]] = field(default_factory=list)

    def record(self, timestamp: float, data: str, stream: str = "o"):
        self.events.append([round(float(timestamp), 3), stream, data])

    def to_asciinema(self) -> str:
        header = {"version": 2, "width": self.width, "height": self.height}
        lines = [json.dumps(header, separators=(",", ":"))]
        lines.extend(json.dumps(event, separators=(",", ":")) for event in self.events)
        return "\n".join(lines)


def fingerprint_http_request(raw_request: str | bytes) -> dict:
    text = raw_request.decode("utf-8", errors="ignore") if isinstance(raw_request, bytes) else str(raw_request)
    lines = text.splitlines()
    request_line = lines[0] if lines else ""
    header_order = []
    headers = {}
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        header_order.append(key)
        headers[key] = value.strip()
    material = json.dumps({"request_line": request_line, "header_order": header_order, "user_agent": headers.get("user-agent", "")}, sort_keys=True)
    return {
        "request_line": request_line,
        "header_order": header_order,
        "user_agent": headers.get("user-agent", ""),
        "fingerprint": hashlib.sha256(material.encode("utf-8")).hexdigest()[:24],
    }


def deception_headers() -> dict:
    return {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "X-Backend-Server": "web-prod-02",
    }


def fake_stack_trace(status_code: int, path: str = "/") -> str:
    template = FAKE_STACK_TRACES.get(int(status_code), FAKE_STACK_TRACES[500])
    return template.format(path=path)


def response_jitter_seconds(path: str = "") -> float:
    base = random.uniform(0.01, 0.08)
    if any(marker in path for marker in ("/api/", "query", "report", "stats")):
        base += random.uniform(0.03, 0.12)
    return base


def randomized_json_payload(data: dict) -> str:
    items = [(k, v) for k, v in data.items() if v is not None or random.choice([True, False])]
    random.shuffle(items)
    separators = random.choice([(",", ":"), (", ", ": ")])
    return json.dumps(dict(items), separators=separators)
