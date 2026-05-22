import os
import unittest
from unittest.mock import patch

import notifications


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.copy()
        notifications._LAST_SENT.clear()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        notifications._LAST_SENT.clear()

    def test_provider_status_never_exposes_secret_values(self):
        os.environ["HONEYPOT_ALERTS_ENABLED"] = "true"
        os.environ["SLACK_WEBHOOK_URL"] = "https://hooks.slack.test/secret"
        os.environ["DISCORD_WEBHOOK_URL"] = "https://discord.test/secret"
        os.environ["TELEGRAM_BOT_TOKEN"] = "123:secret"
        os.environ["TELEGRAM_CHAT_ID"] = "12345"

        status = notifications.provider_status()

        self.assertTrue(status["enabled"])
        self.assertTrue(status["providers"]["slack"]["configured"])
        self.assertTrue(status["providers"]["discord"]["configured"])
        self.assertTrue(status["providers"]["telegram"]["configured"])
        self.assertNotIn("secret", repr(status))

    def test_disabled_alerts_do_not_send(self):
        os.environ["HONEYPOT_ALERTS_ENABLED"] = "false"
        os.environ["SLACK_WEBHOOK_URL"] = "https://hooks.slack.test/secret"

        with patch.object(notifications, "_send_slack") as send_slack:
            result = notifications.send_alert({"attack_category": "Malware Attempt", "service": "ssh", "ip": "1.2.3.4"})

        self.assertFalse(result["sent"])
        send_slack.assert_not_called()

    def test_enabled_high_severity_alert_sends_to_configured_provider(self):
        os.environ["HONEYPOT_ALERTS_ENABLED"] = "true"
        os.environ["HONEYPOT_ALERT_MIN_INTERVAL_SECONDS"] = "0"
        os.environ["SLACK_WEBHOOK_URL"] = "https://hooks.slack.test/secret"

        with patch.object(notifications, "_send_slack", return_value=True) as send_slack:
            result = notifications.send_alert({
                "attack_category": "Malware Attempt",
                "service": "ssh",
                "ip": "1.2.3.4",
                "command": "curl http://example.test/payload.sh",
            })

        self.assertTrue(result["sent"])
        send_slack.assert_called_once()

    def test_low_severity_below_default_threshold_is_suppressed(self):
        os.environ["HONEYPOT_ALERTS_ENABLED"] = "true"
        os.environ["SLACK_WEBHOOK_URL"] = "https://hooks.slack.test/secret"

        with patch.object(notifications, "_send_slack") as send_slack:
            result = notifications.send_alert({"attack_category": "Benign", "service": "http", "ip": "1.2.3.4"})

        self.assertFalse(result["sent"])
        send_slack.assert_not_called()


if __name__ == "__main__":
    unittest.main()
