import unittest

import api
from security import create_token


class CasesAndReportsApiTests(unittest.TestCase):
    def setUp(self):
        self.client = api.app.test_client()
        self.viewer_headers = {"Authorization": f"Bearer {create_token({'username': 'viewer-test', 'role': 'viewer'})}"}
        self.admin_headers = {"Authorization": f"Bearer {create_token({'username': 'admin-test', 'role': 'admin'})}"}

    def test_create_list_and_update_case(self):
        response = self.client.post(
            "/api/cases",
            headers=self.admin_headers,
            json={
                "title": "Investigate high-risk SSH source",
                "severity": "high",
                "source_ip": "203.0.113.10",
                "assignee": "soc-1",
            },
        )
        self.assertEqual(response.status_code, 201)
        created = response.get_json()
        self.assertEqual(created["status"], "open")
        self.assertEqual(created["severity"], "high")

        listed = self.client.get("/api/cases?status=open", headers=self.viewer_headers)
        self.assertEqual(listed.status_code, 200)
        self.assertTrue(any(c["id"] == created["id"] for c in listed.get_json()))

        updated = self.client.patch(
            f"/api/cases/{created['id']}",
            headers=self.admin_headers,
            json={"status": "closed", "summary": "Contained by upstream firewall rule"},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json()["status"], "closed")
        self.assertIsNotNone(updated.get_json()["closed_at"])

    def test_viewer_cannot_create_case(self):
        response = self.client.post("/api/cases", headers=self.viewer_headers, json={"title": "not allowed"})
        self.assertEqual(response.status_code, 403)

    def test_daily_and_weekly_reports_return_rollups(self):
        for period in ("daily", "weekly"):
            response = self.client.get(f"/api/reports/{period}", headers=self.viewer_headers)
            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            self.assertEqual(data["period"], period)
            self.assertIn("summary", data)
            self.assertIn("top_attackers", data)
            self.assertIn("top_asns", data)
            self.assertIn("categories", data)


if __name__ == "__main__":
    unittest.main()
