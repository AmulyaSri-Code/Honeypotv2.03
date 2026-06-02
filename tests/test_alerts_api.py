import os
import unittest
from unittest.mock import patch

import api
from security import create_token


class AlertsApiTests(unittest.TestCase):
    def setUp(self):
        self.client = api.app.test_client()
        self.viewer_headers = {"Authorization": f"Bearer {create_token({'username': 'viewer-test', 'role': 'viewer'})}"}
        self.admin_headers = {"Authorization": f"Bearer {create_token({'username': 'admin-test', 'role': 'admin'})}"}
        self._env = os.environ.copy()
        api._request_attempts.clear()
        api._login_attempts.clear()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_alert_status_requires_auth_and_hides_secrets(self):
        os.environ["HONEYPOT_ALERTS_ENABLED"] = "true"
        os.environ["SLACK_WEBHOOK_URL"] = "https://hooks.slack.test/secret"

        unauth = self.client.get("/api/alerts/status")
        self.assertEqual(unauth.status_code, 401)

        response = self.client.get("/api/alerts/status", headers=self.viewer_headers)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["providers"]["slack"]["configured"])
        self.assertNotIn("secret", repr(data))

    def test_alert_test_requires_admin(self):
        response = self.client.post("/api/alerts/test", headers=self.viewer_headers, json={})
        self.assertEqual(response.status_code, 403)

    def test_alert_test_returns_result_for_admin(self):
        with patch("api.send_alert", return_value={"sent": True, "providers": {"slack": {"ok": True}}}) as send_alert:
            response = self.client.post("/api/alerts/test", headers=self.admin_headers, json={"service": "dashboard"})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["sent"])
        send_alert.assert_called_once()

    def test_alert_config_get_requires_auth_and_hides_secret_values(self):
        os.environ["HONEYPOT_ALERTS_ENABLED"] = "true"
        os.environ["HONEYPOT_ALERT_MIN_SEVERITY"] = "medium"
        os.environ["SLACK_WEBHOOK_URL"] = "https://hooks.slack.test/secret"

        unauth = self.client.get("/api/alerts/config")
        self.assertEqual(unauth.status_code, 401)

        response = self.client.get("/api/alerts/config", headers=self.viewer_headers)

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["enabled"])
        self.assertEqual(data["min_severity"], "medium")
        self.assertTrue(data["providers"]["slack"]["configured"])
        self.assertEqual(data["providers"]["slack"]["value"], "")
        self.assertNotIn("secret", repr(data))

    def test_alert_config_update_requires_admin_and_updates_runtime_environment(self):
        viewer_response = self.client.put("/api/alerts/config", headers=self.viewer_headers, json={"enabled": True})
        self.assertEqual(viewer_response.status_code, 403)

        with patch("api._write_env_updates") as write_env_updates:
            response = self.client.put(
                "/api/alerts/config",
                headers=self.admin_headers,
                json={
                    "enabled": True,
                    "min_severity": "critical",
                    "providers": {
                        "slack": "https://hooks.slack.test/new-secret",
                        "n8n": "https://n8n.example.test/webhook/honeypot",
                    },
                },
            )

        write_env_updates.assert_called_once()
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["config"]["providers"]["slack"]["configured"])
        self.assertEqual(os.environ["HONEYPOT_ALERTS_ENABLED"], "true")
        self.assertEqual(os.environ["HONEYPOT_ALERT_MIN_SEVERITY"], "critical")
        self.assertEqual(os.environ["SLACK_WEBHOOK_URL"], "https://hooks.slack.test/new-secret")
        self.assertEqual(os.environ["N8N_WEBHOOK_URL"], "https://n8n.example.test/webhook/honeypot")
        self.assertNotIn("new-secret", repr(data))


if __name__ == "__main__":
    unittest.main()
