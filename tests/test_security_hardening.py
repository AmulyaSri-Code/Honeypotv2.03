import tempfile
import unittest
from unittest.mock import patch

import api
import main
from security import create_token


class SecurityHardeningTests(unittest.TestCase):
    def setUp(self):
        self.client = api.app.test_client()
        self.viewer_headers = {"Authorization": f"Bearer {create_token({'username': 'viewer-test', 'role': 'viewer'})}"}
        self.admin_headers = {"Authorization": f"Bearer {create_token({'username': 'admin-test', 'role': 'admin'})}"}

    def test_sensitive_telemetry_requires_authentication(self):
        protected_paths = [
            "/api/stats",
            "/api/connections",
            "/api/commands",
            "/api/attacks",
            "/api/services",
            "/api/threats/summary",
        ]

        for path in protected_paths:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 401)

    def test_viewer_token_can_read_sensitive_telemetry(self):
        for path in ("/api/stats", "/api/connections", "/api/commands", "/api/attacks", "/api/services", "/api/threats/summary"):
            with self.subTest(path=path):
                response = self.client.get(path, headers=self.viewer_headers)
                self.assertEqual(response.status_code, 200)

    def test_legacy_basic_auth_defaults_do_not_authorize_admin_endpoints(self):
        response = self.client.get("/api/users", headers={"Authorization": "Basic YWRtaW46c2VjcmV0"})
        self.assertEqual(response.status_code, 401)

    def test_default_basic_auth_credentials_are_disabled_without_env(self):
        with patch.dict(api.os.environ, {}, clear=True):
            self.assertFalse(api.check_auth("admin", "secret"))

    def test_bootstrap_admin_defaults_to_admin_admin_for_local_login(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_db = f"{tmpdir}/honeypot.db"
            api.HoneypotDatabase(test_db)
            with patch.object(api, "DB_PATH", test_db), patch.dict(api.os.environ, {}, clear=True):
                api._request_attempts.clear()
                api._login_attempts.clear()
                api.bootstrap_admin()
                response = self.client.post(
                    "/api/auth/login",
                    json={"username": "admin", "password": "admin"},
                )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json().get("access_token"))

    def test_bootstrap_refreshes_existing_builtin_admin_to_admin_password(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_db = f"{tmpdir}/honeypot.db"
            api.HoneypotDatabase(test_db)
            conn = api.sqlite3.connect(test_db)
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
                ("admin", api.hash_password("old-secret"), api.utc_now()),
            )
            conn.commit()
            conn.close()
            with patch.object(api, "DB_PATH", test_db), patch.dict(api.os.environ, {}, clear=True):
                api._request_attempts.clear()
                api._login_attempts.clear()
                api.bootstrap_admin()
                response = self.client.post(
                    "/api/auth/login",
                    json={"username": "admin", "password": "admin"},
                )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json().get("access_token"))

    def test_dashboard_security_headers_include_csp_and_permissions_policy(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers.get("Permissions-Policy"), "geolocation=(), microphone=(), camera=()")

    def test_main_defaults_dashboard_bind_to_loopback(self):
        with patch.dict(main.os.environ, {}, clear=True):
            self.assertEqual(main.dashboard_bind_host(), "127.0.0.1")

    def test_limit_query_is_clamped_to_positive_bounds(self):
        response = self.client.get("/api/commands?limit=-1", headers=self.viewer_headers)
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(response.get_json()), 1)

        response = self.client.get("/api/commands?limit=999999", headers=self.viewer_headers)
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(response.get_json()), 500)

    def test_x_forwarded_for_is_ignored_without_trusted_proxy(self):
        with patch.dict(api.os.environ, {"HONEYPOT_TRUSTED_PROXIES": ""}, clear=False):
            with api.app.test_request_context("/", environ_base={"REMOTE_ADDR": "198.51.100.10"}, headers={"X-Forwarded-For": "203.0.113.99"}):
                self.assertEqual(api.client_ip(), "198.51.100.10")

    def test_x_forwarded_for_is_used_for_configured_trusted_proxy(self):
        with patch.dict(api.os.environ, {"HONEYPOT_TRUSTED_PROXIES": "198.51.100.10"}, clear=False):
            with api.app.test_request_context("/", environ_base={"REMOTE_ADDR": "198.51.100.10"}, headers={"X-Forwarded-For": "203.0.113.99, 198.51.100.10"}):
                self.assertEqual(api.client_ip(), "203.0.113.99")


if __name__ == "__main__":
    unittest.main()
