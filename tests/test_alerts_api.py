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


if __name__ == "__main__":
    unittest.main()
