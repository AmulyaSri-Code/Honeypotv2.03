import re
import unittest
from pathlib import Path


DASHBOARD = Path(__file__).resolve().parents[1] / "dashboard" / "index.html"


class DashboardUiTests(unittest.TestCase):
    def setUp(self):
        self.html = DASHBOARD.read_text(encoding="utf-8")

    def test_dashboard_has_premium_motion_layers_and_reduced_motion_guard(self):
        required = [
            "class=\"orbital-bg\"",
            "class=\"scanline-overlay\"",
            "@keyframes aurora-drift",
            "@keyframes panel-rise",
            "@media (prefers-reduced-motion: reduce)",
        ]
        for snippet in required:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, self.html)

    def test_browser_prompt_login_is_replaced_with_modal_login(self):
        self.assertNotIn("window.prompt", self.html)
        self.assertIn("id=\"login-modal\"", self.html)
        self.assertIn("function showLoginModal", self.html)
        self.assertIn("function submitLogin", self.html)
        self.assertIn("aria-modal=\"true\"", self.html)

    def test_login_page_looks_like_real_auth_screen_and_mentions_private_credentials(self):
        required = [
            "class=\"login-page\"",
            "Use the admin account created by setup.py",
            "placeholder=\"operator\"",
            "autocomplete=\"current-password\"",
            "Sign in to dashboard",
        ]
        for snippet in required:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, self.html)

    def test_dashboard_has_toasts_and_animated_activity_rows(self):
        self.assertIn("id=\"toast-stack\"", self.html)
        self.assertIn("function showToast", self.html)
        self.assertRegex(self.html, r"class=\"[^\"]*feed-row")
        self.assertIn("@keyframes feed-in", self.html)
        self.assertIn("@keyframes marker-ripple", self.html)

    def test_dashboard_has_responsive_mobile_breakpoints(self):
        breakpoints = re.findall(r"@media \(max-width:\s*([0-9]+)px\)", self.html)
        self.assertTrue(any(int(bp) <= 900 for bp in breakpoints), breakpoints)
        self.assertIn("grid-template-columns: 1fr", self.html)
    def test_dashboard_has_soc_navigation_and_operator_workbench(self):
        required = [
            "<title>HoneyPot v3 | Defensive Honeypot Threat Intelligence Dashboard</title>",
            "HoneyPot v3 Defense Console",
            "Defense Console",
            "id=\"nav-overview\"",
            "id=\"analyst-workbench\"",
            "id=\"pause-feed\"",
            "id=\"session-terminal\"",
            "class=\"shell-line\"",
        ]
        for snippet in required:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, self.html)

    def test_dashboard_has_operator_ticker_and_feed_lens_filters(self):
        required = [
            "id=\"mission-ticker\"",
            "class=\"threat-lens\"",
            "data-feed-filter=\"critical\"",
            "function setFeedFilter",
            "@keyframes ticker-glow",
            "feed-filter-active",
        ]
        for snippet in required:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, self.html)

    def test_left_navigation_targets_dashboard_sections(self):
        required = [
            "data-nav-target=\"live-attack-panel\"",
            "data-nav-target=\"sessions-panel\"",
            "data-nav-target=\"credential-panel\"",
            "data-nav-target=\"alerts-panel\"",
            "data-nav-target=\"reports-panel\"",
            "id=\"live-attack-panel\"",
            "id=\"sessions-panel\"",
            "id=\"credential-panel\"",
            "id=\"alerts-panel\"",
            "id=\"reports-panel\"",
            "function activateNavSection",
        ]
        for snippet in required:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, self.html)

    def test_send_test_alert_button_handles_api_sent_success_shape(self):
        self.assertIn("const ok=!!(r?.success||r?.sent||r?.result?.sent)", self.html)
        self.assertIn("Not sent:", self.html)

    def test_alert_channel_panel_includes_n8n_automation(self):
        self.assertIn("Slack · Telegram · Discord · n8n", self.html)
        self.assertIn("'slack','telegram','discord','n8n'", self.html)

    def test_dashboard_has_alert_setup_panel_for_admin_connections(self):
        required = [
            "id=\"alert-settings-form\"",
            "id=\"alert-slack-webhook\"",
            "id=\"alert-discord-webhook\"",
            "id=\"alert-telegram-token\"",
            "id=\"alert-telegram-chat\"",
            "id=\"alert-n8n-webhook\"",
            "function loadAlertConfig",
            "function saveAlertConfig",
            "/api/alerts/config",
            "Save alert connections",
        ]
        for snippet in required:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, self.html)

    def test_dashboard_exposes_safe_operator_metadata_without_indexing_admin_ui(self):
        required = [
            "name=\"description\"",
            "name=\"robots\" content=\"noindex, nofollow\"",
            "property=\"og:title\"",
            "application/ld+json",
            "class=\"seo-summary\"",
            "Open-source defensive honeypot and threat intelligence dashboard",
        ]
        for snippet in required:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, self.html)
        self.assertNotIn("index, follow, max-image-preview", self.html)


if __name__ == "__main__":
    unittest.main()
