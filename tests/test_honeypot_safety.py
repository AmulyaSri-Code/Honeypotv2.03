import unittest
from unittest.mock import patch

import honeypot


class HoneypotSafetyTests(unittest.TestCase):
    def test_sanitize_event_text_escapes_controls_and_truncates(self):
        raw = "whoami\nFAKE LOG\r\x1b[31m" + ("A" * 3000)
        cleaned = honeypot.sanitize_event_text(raw, max_chars=80)

        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\r", cleaned)
        self.assertNotIn("\x1b", cleaned)
        self.assertIn("\\n", cleaned)
        self.assertLessEqual(len(cleaned), 80)
        self.assertTrue(cleaned.endswith("...[truncated]"))

    def test_private_network_geolocation_stays_local_and_offline(self):
        with patch("honeypot.urllib.request.urlopen") as urlopen:
            geo = honeypot.get_geolocation("172.16.1.10")

        urlopen.assert_not_called()
        self.assertEqual(geo["country"], "Local Network")
        self.assertEqual(geo["query"], "172.16.1.10")

    def test_service_connection_guard_enforces_global_and_per_ip_caps(self):
        class DummyService(honeypot.Service):
            def start(self):
                pass

            def stop(self):
                pass

        svc = DummyService("dummy", 1, None, None)
        svc.max_connections = 2
        svc.max_connections_per_ip = 1

        self.assertTrue(svc._try_acquire_connection(("203.0.113.10", 1234)))
        self.assertFalse(svc._try_acquire_connection(("203.0.113.10", 1235)))
        self.assertTrue(svc._try_acquire_connection(("203.0.113.11", 1236)))
        self.assertFalse(svc._try_acquire_connection(("203.0.113.12", 1237)))

        svc._release_connection(("203.0.113.10", 1234))
        self.assertTrue(svc._try_acquire_connection(("203.0.113.12", 1237)))


if __name__ == "__main__":
    unittest.main()
