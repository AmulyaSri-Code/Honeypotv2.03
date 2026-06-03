import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
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

    def test_bootstrap_admin_requires_configured_credentials_by_default(self):
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

        self.assertEqual(response.status_code, 401)

    def test_bootstrap_admin_uses_explicit_env_credentials_and_sets_dashboard_cookie(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_db = f"{tmpdir}/honeypot.db"
            api.HoneypotDatabase(test_db)
            env = {"HONEYPOT_ADMIN_USER": "operator", "HONEYPOT_ADMIN_PASS": "StrongPrivatePass123!"}
            with patch.object(api, "DB_PATH", test_db), patch.dict(api.os.environ, env, clear=True):
                api._request_attempts.clear()
                api._login_attempts.clear()
                api.bootstrap_admin()
                response = self.client.post(
                    "/api/auth/login",
                    json={"username": "operator", "password": "StrongPrivatePass123!"},
                )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json().get("access_token"))
        self.assertIn("honeypot_session=", response.headers.get("Set-Cookie", ""))

    def test_dashboard_root_redirects_to_login_without_session_cookie(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers.get("Location", ""))

    def test_dashboard_security_headers_include_csp_and_permissions_policy(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers.get("Permissions-Policy"), "geolocation=(), microphone=(), camera=()")
        self.assertEqual(response.headers.get("Cache-Control"), "no-store")

    def test_public_discovery_files_discourage_indexing_and_reference_public_url(self):
        with patch.dict(api.os.environ, {
            "HONEYPOT_PUBLIC_URL": "https://example.com/honeypot",
            "HONEYPOT_INDEXNOW_KEY": "abc123indexkey",
        }, clear=False):
            robots = self.client.get("/robots.txt")
            sitemap = self.client.get("/sitemap.xml")

        self.assertEqual(robots.status_code, 200)
        self.assertIn("Disallow: /", robots.get_data(as_text=True))
        self.assertNotIn("Allow: /", robots.get_data(as_text=True))
        self.assertNotIn("Sitemap:", robots.get_data(as_text=True))
        self.assertIn("Host: https://example.com/honeypot", robots.get_data(as_text=True))
        self.assertEqual(robots.headers.get("Cache-Control"), "public, max-age=300")
        self.assertEqual(sitemap.status_code, 200)
        self.assertIn("<loc>https://example.com/honeypot/</loc>", sitemap.get_data(as_text=True))
        self.assertIn("<loc>https://example.com/honeypot/robots.txt</loc>", sitemap.get_data(as_text=True))
        self.assertIn("<loc>https://example.com/honeypot/indexnow-key.txt</loc>", sitemap.get_data(as_text=True))
        self.assertEqual(sitemap.headers.get("Cache-Control"), "public, max-age=300")

    def test_indexing_verification_hooks_are_public_and_cacheable(self):
        env = {
            "HONEYPOT_GOOGLE_SITE_VERIFICATION": "google-token-123",
            "HONEYPOT_BING_SITE_VERIFICATION": "bing-token-456",
            "HONEYPOT_INDEXNOW_KEY": "abc123indexkey",
        }
        with patch.dict(api.os.environ, env, clear=False):
            meta = self.client.get("/api/indexing/meta")
            key = self.client.get("/indexnow-key.txt")

        self.assertEqual(meta.status_code, 200)
        payload = meta.get_json()
        self.assertEqual(payload["google_site_verification"], "google-token-123")
        self.assertEqual(payload["bing_site_verification"], "bing-token-456")
        self.assertIn("/sitemap.xml", payload["sitemap"])
        self.assertEqual(key.status_code, 200)
        self.assertEqual(key.get_data(as_text=True).strip(), "abc123indexkey")
        self.assertEqual(key.headers.get("Cache-Control"), "public, max-age=300")

    def test_dashboard_homepage_redirects_to_private_login_without_session(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers.get("Location"), "/login")
        self.assertEqual(response.headers.get("Cache-Control"), "public, max-age=300")

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

    def test_persistent_rate_limit_uses_database_table(self):
        import api
        with tempfile.TemporaryDirectory() as tmpdir:
            test_db = str(Path(tmpdir) / "honeypot.db")
            api.HoneypotDatabase(test_db)
            with patch.object(api, "DB_PATH", test_db), patch.dict(api.os.environ, {"HONEYPOT_RATE_LIMIT_BACKEND": "sqlite"}, clear=False):
                api.clear_rate_limit("request", "198.51.100.10")
                self.assertFalse(api.persistent_rate_limited("request", "198.51.100.10", 60, 2))
                api.mark_persistent_rate("request", "198.51.100.10")
                self.assertFalse(api.persistent_rate_limited("request", "198.51.100.10", 60, 2))
                api.mark_persistent_rate("request", "198.51.100.10")
                self.assertTrue(api.persistent_rate_limited("request", "198.51.100.10", 60, 2))

                conn = api.get_db()
                count = conn.execute("SELECT COUNT(*) FROM rate_limits WHERE scope='request' AND identity='198.51.100.10'").fetchone()[0]
                conn.close()
        self.assertEqual(count, 2)

    def test_setup_status_endpoint_returns_safe_operator_booleans(self):
        env = {
            "HONEYPOT_AUTH_SECRET": "a" * 48,
            "HONEYPOT_ADMIN_PASS": "StrongAdminPass123!",
            "HONEYPOT_BIND_HOST": "127.0.0.1",
            "HONEYPOT_DB_PATH": "honeypot.db",
            "SLACK_WEBHOOK_URL": "https://hooks.slack.example/redacted-secret",
            "TELEGRAM_BOT_TOKEN": "123:secret-token",
            "TELEGRAM_CHAT_ID": "12345",
        }
        with patch.dict(api.os.environ, env, clear=False):
            headers = {"Authorization": f"Bearer {create_token({'username': 'viewer-test', 'role': 'viewer'})}"}
            response = self.client.get("/api/setup/status", headers=headers)

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        for key in ("env_exists", "auth_secret_strong", "admin_configured", "dashboard_private", "db_writable", "ml_loaded", "alerts_enabled", "providers_configured"):
            self.assertIn(key, payload)
        self.assertTrue(payload["auth_secret_strong"])
        self.assertTrue(payload["admin_configured"])
        self.assertTrue(payload["dashboard_private"])
        self.assertIsInstance(payload["providers_configured"]["slack"], bool)
        serialized = response.get_data(as_text=True)
        self.assertNotIn("redacted-secret", serialized)
        self.assertNotIn("secret-token", serialized)

    def test_setup_status_endpoint_requires_authentication(self):
        response = self.client.get("/api/setup/status")
        self.assertEqual(response.status_code, 401)


class ProductionStartupAndBootstrapTests(unittest.TestCase):
    def test_production_startup_rejects_default_auth_secret(self):
        import api
        with patch.dict(os.environ, {"FLASK_ENV": "production", "HONEYPOT_AUTH_SECRET": "change-me-in-production"}, clear=False):
            with self.assertRaises(RuntimeError):
                api.validate_production_startup_config()

    def test_production_startup_accepts_strong_secrets(self):
        import api
        with patch.dict(os.environ, {
            "FLASK_ENV": "production",
            "HONEYPOT_AUTH_SECRET": "a" * 48,
            "HONEYPOT_ADMIN_PASS": "StrongAdminPass123!",
            "HONEYPOT_ALLOW_DEFAULT_ADMIN": "false",
        }, clear=False):
            self.assertTrue(api.validate_production_startup_config())

    def test_direct_api_py_startup_rejects_weak_production_secret(self):
        env = {
            **os.environ,
            "FLASK_ENV": "production",
            "HONEYPOT_AUTH_SECRET": "change-me-in-production",
            "HONEYPOT_ADMIN_PASS": "StrongAdminPass123!",
            "HONEYPOT_DASHBOARD_PORT": "5999",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = subprocess.run(
            [sys.executable, "api.py"],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            text=True,
            capture_output=True,
            timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HONEYPOT_AUTH_SECRET", result.stderr + result.stdout)

    def test_remote_bootstrap_requires_token_by_default(self):
        import api
        with patch.dict(os.environ, {"FLASK_ENV": "development", "HONEYPOT_AUTH_SECRET": "a" * 48}, clear=False):
            with tempfile.TemporaryDirectory() as tmpdir, patch.object(api, "DB_PATH", str(Path(tmpdir) / "honeypot.db")):
                api.hp_db = api.HoneypotDatabase(api.DB_PATH)
                response = api.app.test_client().post(
                    "/api/auth/bootstrap",
                    json={"username": "operator", "password": "StrongAdminPass123!"},
                    environ_base={"REMOTE_ADDR": "203.0.113.10"},
                )
        self.assertEqual(response.status_code, 403)

    def test_bootstrap_token_allows_remote_first_admin(self):
        import api
        token = "b" * 40
        with patch.dict(os.environ, {"FLASK_ENV": "development", "HONEYPOT_BOOTSTRAP_TOKEN": token, "HONEYPOT_AUTH_SECRET": "a" * 48}, clear=False):
            with tempfile.TemporaryDirectory() as tmpdir, patch.object(api, "DB_PATH", str(Path(tmpdir) / "honeypot.db")):
                api.hp_db = api.HoneypotDatabase(api.DB_PATH)
                response = api.app.test_client().post(
                    "/api/auth/bootstrap",
                    json={"username": "operator", "password": "StrongAdminPass123!"},
                    headers={"X-Bootstrap-Token": token},
                    environ_base={"REMOTE_ADDR": "203.0.113.10"},
                )
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
