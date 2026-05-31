import importlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class CriticalHardeningTests(unittest.TestCase):
    def test_event_write_buffer_requeues_batch_when_sink_fails(self):
        from v31_core import EventWriteBuffer

        attempts = []
        def flaky_sink(batch):
            attempts.append(list(batch))
            if len(attempts) == 1:
                raise RuntimeError("transient sqlite lock")

        buffer = EventWriteBuffer(flush_interval=10, sink=flaky_sink)
        buffer.add({"type": "command", "value": "id"})

        with self.assertRaises(RuntimeError):
            buffer.flush()

        self.assertEqual(buffer.pending_count(), 1)
        self.assertEqual(buffer.flush(), 1)
        self.assertEqual(len(attempts), 2)

    def test_honeypot_database_batches_command_writes_and_flushes_on_close(self):
        import honeypot
        from v31_core import EventWriteBuffer

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "honeypot.db")
            with patch.object(honeypot, "enrich_ip", return_value={"country": "CachedLand"}):
                db = honeypot.HoneypotDatabase(db_path)
                self.assertIsInstance(db.command_buffer, EventWriteBuffer)
                cid = db.log_connection("8.8.8.8", 2222, "ssh")
                db.log_command("8.8.8.8", "ssh", "whoami", cid)
                db.log_command("8.8.8.8", "ssh", "id", cid)
                self.assertGreaterEqual(db.command_buffer.pending_count(), 2)
                db.close()

            conn = sqlite3.connect(db_path)
            rows = conn.execute("SELECT command FROM commands ORDER BY id").fetchall()
            conn.close()

        self.assertEqual([row[0] for row in rows], ["whoami", "id"])

    def test_connection_logging_uses_single_enrichment_path(self):
        import honeypot

        with tempfile.TemporaryDirectory() as tmpdir:
            db = honeypot.HoneypotDatabase(str(Path(tmpdir) / "honeypot.db"))
            with patch.object(honeypot, "enrich_ip", return_value={"country": "CachedLand"}) as enrich, \
                 patch.object(honeypot, "get_geolocation", side_effect=AssertionError("legacy duplicate lookup should not run")):
                cid = honeypot.log_sensor_connection(db, "8.8.8.8", 2222, "ssh")
                db.close()

        self.assertIsInstance(cid, int)
        enrich.assert_called_once()

    def test_lazy_classifier_updates_session_commands_after_disconnect(self):
        import honeypot

        with tempfile.TemporaryDirectory() as tmpdir:
            db = honeypot.HoneypotDatabase(str(Path(tmpdir) / "honeypot.db"))
            with patch.object(honeypot, "enrich_ip", return_value={"country": "CachedLand"}):
                cid = db.log_connection("8.8.8.8", 2222, "ssh")
            db.log_command("8.8.8.8", "ssh", "whoami", cid)
            db.flush_command_buffer()
            future = honeypot.classify_session_after_disconnect(db, cid, ["whoami"], predict_fn=lambda text: "Recon")
            self.assertEqual(future.result(timeout=2)["attack_category"], "Recon")

            conn = sqlite3.connect(db.db_path)
            category = conn.execute("SELECT attack_category FROM commands WHERE connection_id=?", (cid,)).fetchone()[0]
            conn.close()
            db.close()

        self.assertEqual(category, "Recon")

    def test_session_replay_is_persisted_and_served_by_api(self):
        import api
        import honeypot
        from security import create_token

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "honeypot.db")
            db = honeypot.HoneypotDatabase(db_path)
            with patch.object(honeypot, "enrich_ip", return_value={"country": "CachedLand"}):
                cid = db.log_connection("8.8.8.8", 2222, "ssh")
            db.record_session_replay(cid, 0.1, "whoami\n", "i")
            db.record_session_replay(cid, 0.2, "admin\n", "o")
            db.close()

            headers = {"Authorization": f"Bearer {create_token({'username': 'viewer', 'role': 'viewer'})}"}
            with patch.object(api, "DB_PATH", db_path):
                response = api.app.test_client().get(f"/api/sessions/{cid}/replay", headers=headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/x-asciicast")
        lines = response.get_data(as_text=True).splitlines()
        self.assertIn('"version":2', lines[0])
        self.assertIn('whoami', lines[1])

    def test_api_import_uses_env_db_path_instead_of_repo_db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "isolated.db")
            code = "import api, os; print(api.DB_PATH); assert api.DB_PATH == os.environ['HONEYPOT_DB_PATH']"
            result = subprocess.run(
                [sys.executable, "-c", code],
                cwd=ROOT,
                env={**os.environ, "HONEYPOT_DB_PATH": db_path, "PYTHONDONTWRITEBYTECODE": "1"},
                text=True,
                capture_output=True,
                timeout=20,
            )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_compose_defaults_do_not_expose_management_or_unauthenticated_data_services(self):
        text = (ROOT / "docker-compose.yml").read_text()
        self.assertIn('"127.0.0.1:5050:5050"', text)
        self.assertNotIn('"5050:5050"   # Dashboard API', text)
        self.assertNotIn('"9200:9200"', text)
        self.assertNotIn("xpack.security.enabled=false", text)
        self.assertNotIn("/var/run/docker.sock:/var/run/docker.sock", text)

    def test_n8n_encryption_key_has_no_known_fallback(self):
        text = (ROOT / "docker-compose.yml").read_text()
        self.assertNotIn("replace_with_a_32_plus_character_secret", text)
        self.assertIn("N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY:?set_N8N_ENCRYPTION_KEY_in_.env}", text)

    def test_dashboard_is_noindex_by_default(self):
        html = (ROOT / "dashboard" / "index.html").read_text()
        self.assertIn('name="robots" content="noindex, nofollow"', html)
        self.assertNotIn('index, follow, max-image-preview', html)
        self.assertIn('type="application/ld+json"', html)


if __name__ == "__main__":
    unittest.main()
