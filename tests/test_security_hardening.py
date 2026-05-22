import unittest
from unittest.mock import patch

import api
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
