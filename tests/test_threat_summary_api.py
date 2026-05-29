import unittest

import api
from security import create_token


class ThreatSummaryApiTests(unittest.TestCase):
    def setUp(self):
        self.client = api.app.test_client()
        self.viewer_headers = {"Authorization": f"Bearer {create_token({'username': 'viewer-test', 'role': 'viewer'})}"}

    def test_threat_summary_endpoint_returns_operational_intelligence(self):
        response = self.client.get("/api/threats/summary", headers=self.viewer_headers)

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsInstance(data, dict)
        self.assertIn("risk_score", data)
        self.assertIn("risk_level", data)
        self.assertIn("top_attackers", data)
        self.assertIn("top_countries", data)
        self.assertIn("top_asns", data)
        self.assertIn("reputation", data)
        self.assertIn("cases", data)
        self.assertIn("recent_critical", data)
        self.assertIn("timeline", data)
        self.assertIn("deployment", data)
        self.assertIsInstance(data["risk_score"], int)
        self.assertGreaterEqual(data["risk_score"], 0)
        self.assertLessEqual(data["risk_score"], 100)
        self.assertIsInstance(data["top_attackers"], list)
        self.assertIsInstance(data["top_countries"], list)
        self.assertIsInstance(data["recent_critical"], list)
        self.assertIsInstance(data["timeline"], list)
        self.assertIsInstance(data["deployment"], dict)

    def test_threat_summary_deployment_warns_on_default_secret(self):
        response = self.client.get("/api/threats/summary", headers=self.viewer_headers)
        data = response.get_json()

        checks = data["deployment"].get("checks", [])
        self.assertTrue(any(check["id"] == "auth_secret" for check in checks))
        self.assertTrue(any(check["status"] in {"pass", "warn"} for check in checks))


if __name__ == "__main__":
    unittest.main()
