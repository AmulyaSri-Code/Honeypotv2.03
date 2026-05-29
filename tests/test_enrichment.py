import os
import unittest
from unittest.mock import patch

import enrichment


class EnrichmentTests(unittest.TestCase):
    def test_private_ip_uses_local_enrichment(self):
        data = enrichment.enrich_ip("127.0.0.1")

        self.assertEqual(data["enrichment_provider"], "local")
        self.assertEqual(data["reputation_level"], "internal")
        self.assertIn("non_public_ip", data["reputation_flags"])

    def test_ip_api_reputation_flags_proxy_hosting(self):
        score, flags = enrichment.reputation_from_ip_api(
            {"proxy": True, "hosting": True, "mobile": False, "isp": "Example Cloud Hosting", "org": ""}
        )

        self.assertGreaterEqual(score, 60)
        self.assertIn("proxy_or_vpn", flags)
        self.assertIn("hosting_provider", flags)
        self.assertIn("infrastructure_asn", flags)

    def test_enrichment_disabled_does_not_call_external_provider(self):
        with patch.dict(os.environ, {"HONEYPOT_ENRICHMENT_ENABLED": "false"}):
            with patch.object(enrichment, "ENABLE_EXTERNAL", False):
                data = enrichment.enrich_ip("8.8.8.8")

        self.assertEqual(data["enrichment_provider"], "disabled")
        self.assertEqual(data["reputation_score"], 0)


if __name__ == "__main__":
    unittest.main()
