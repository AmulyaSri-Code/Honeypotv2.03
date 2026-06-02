import importlib.util
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_setup_module():
    spec = importlib.util.spec_from_file_location("honeypot_setup", ROOT / "setup.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SetupConfigTests(unittest.TestCase):
    def test_build_env_config_uses_supplied_credentials_and_generates_secret(self):
        setup = load_setup_module()

        config = setup.build_env_config(
            admin_user="operator",
            admin_pass="StrongPass123!",
            bind_host="127.0.0.1",
            sensor_bind_host="127.0.0.1",
            dashboard_port="5051",
            alerts_enabled=True,
            alert_min_severity="medium",
            slack_webhook_url="https://hooks.slack.test/token",
            n8n_webhook_url="https://n8n.test/webhook/honeypot",
            discord_webhook_url="",
            telegram_bot_token="123:token",
            telegram_chat_id="999",
        )

        self.assertEqual(config["HONEYPOT_ADMIN_USER"], "operator")
        self.assertEqual(config["HONEYPOT_ADMIN_PASS"], "StrongPass123!")
        self.assertEqual(config["HONEYPOT_BIND_HOST"], "127.0.0.1")
        self.assertEqual(config["HONEYPOT_SENSOR_BIND_HOST"], "127.0.0.1")
        self.assertEqual(config["HONEYPOT_DASHBOARD_PORT"], "5051")
        self.assertEqual(config["HONEYPOT_ALERTS_ENABLED"], "true")
        self.assertEqual(config["HONEYPOT_ALERT_MIN_SEVERITY"], "medium")
        self.assertEqual(config["N8N_WEBHOOK_URL"], "https://n8n.test/webhook/honeypot")
        self.assertTrue(config["HONEYPOT_AUTH_SECRET"])
        self.assertNotEqual(config["HONEYPOT_AUTH_SECRET"], "change-me-in-production")
        self.assertEqual(config["HONEYPOT_ALLOW_DEFAULT_ADMIN"], "false")

    def test_weak_or_default_admin_password_is_rejected(self):
        setup = load_setup_module()

        for bad_password in ("secret", "password", "admin", "123", "shortpass") :
            with self.subTest(bad_password=bad_password):
                with self.assertRaises(ValueError):
                    setup.build_env_config(admin_user="admin", admin_pass=bad_password)

    def test_write_env_file_is_owner_only_and_refuses_overwrite_without_force(self):
        setup = load_setup_module()
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env"
            config = setup.build_env_config(admin_user="operator", admin_pass="StrongPass123!")

            setup.write_env_file(env_path, config, force=False)
            mode = stat.S_IMODE(env_path.stat().st_mode)
            self.assertEqual(mode, 0o600)
            text = env_path.read_text()
            self.assertIn("HONEYPOT_ADMIN_USER=operator", text)
            self.assertIn("HONEYPOT_ADMIN_PASS=StrongPass123!", text)

            with self.assertRaises(FileExistsError):
                setup.write_env_file(env_path, config, force=False)

    def test_env_loader_reads_generated_env_without_overriding_existing_values(self):
        import env_loader

        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env"
            env_path.write_text("HONEYPOT_ADMIN_USER=file-user\nHONEYPOT_DASHBOARD_PORT=5059\n")
            old_user = os.environ.get("HONEYPOT_ADMIN_USER")
            old_port = os.environ.get("HONEYPOT_DASHBOARD_PORT")
            try:
                os.environ["HONEYPOT_ADMIN_USER"] = "existing-user"
                os.environ.pop("HONEYPOT_DASHBOARD_PORT", None)
                loaded = env_loader.load_env_file(env_path)
                self.assertIn("HONEYPOT_ADMIN_USER", loaded)
                self.assertEqual(os.environ["HONEYPOT_ADMIN_USER"], "existing-user")
                self.assertEqual(os.environ["HONEYPOT_DASHBOARD_PORT"], "5059")
            finally:
                if old_user is None:
                    os.environ.pop("HONEYPOT_ADMIN_USER", None)
                else:
                    os.environ["HONEYPOT_ADMIN_USER"] = old_user
                if old_port is None:
                    os.environ.pop("HONEYPOT_DASHBOARD_PORT", None)
                else:
                    os.environ["HONEYPOT_DASHBOARD_PORT"] = old_port

    def test_quick_deploy_assets_exist_and_keep_generated_credentials_ignored(self):
        quick_script = ROOT / "scripts" / "quick_deploy.sh"
        quick_docs = ROOT / "QUICK_DEPLOY.md"
        makefile = ROOT / "Makefile"
        gitignore = (ROOT / ".gitignore").read_text()

        self.assertTrue(quick_script.exists())
        self.assertIn("quick_deploy.sh docker", quick_docs.read_text())
        self.assertIn("deploy:", makefile.read_text())
        self.assertIn(".deploy-credentials.txt", gitignore)

    def test_quick_deploy_help_is_fast_and_documents_modes(self):
        result = subprocess.run(
            ["bash", "scripts/quick_deploy.sh", "help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=5,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("quick_deploy.sh docker", result.stderr)
        self.assertIn("quick_deploy.sh local", result.stderr)


if __name__ == "__main__":
    unittest.main()
