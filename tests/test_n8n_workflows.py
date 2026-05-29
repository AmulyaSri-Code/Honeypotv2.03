import json
import unittest
from pathlib import Path


class N8nWorkflowTemplateTests(unittest.TestCase):
    def test_critical_alert_workflow_avoids_brittle_if_node(self):
        workflow = json.loads(Path("n8n-workflows/honeypot-v3-critical-alert.json").read_text())
        node_types = {node["type"] for node in workflow["nodes"]}

        self.assertIn("n8n-nodes-base.webhook", node_types)
        self.assertIn("n8n-nodes-base.code", node_types)
        self.assertIn("n8n-nodes-base.respondToWebhook", node_types)
        self.assertNotIn("n8n-nodes-base.if", node_types)
        self.assertTrue(workflow.get("active"))

    def test_report_workflow_json_loads(self):
        workflow = json.loads(Path("n8n-workflows/honeypot-v3-daily-weekly-reports.json").read_text())

        self.assertEqual(workflow["id"], "honeypot-v3-daily-weekly-reports")
        self.assertTrue(workflow["nodes"])


if __name__ == "__main__":
    unittest.main()
