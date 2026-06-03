"""
Real-time attack classifier for HoneyPot v3.

The honeypot calls predict() on attacker-controlled commands from multiple
services, so this module must never crash request/session handling. Model loading
is lazy, cached, and intentionally fails closed to "Unknown" when artifacts are
missing, corrupted, or incompatible with the installed sklearn version.
"""
import hashlib
import os
import pickle
import re
from typing import Any

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(SCRIPT_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(SCRIPT_DIR, "vectorizer.pkl")
MANIFEST_PATH = os.path.join(SCRIPT_DIR, "artifacts.sha256")

_classifier = None
_vectorizer = None
_load_error = None


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_hashes() -> dict[str, str]:
    hashes = {}
    if not os.path.exists(MANIFEST_PATH):
        return hashes
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2 and len(parts[0]) == 64:
                hashes[parts[-1]] = parts[0].lower()
    return hashes


def _artifacts_verified() -> bool:
    hashes = _manifest_hashes()
    required = {"model.pkl": MODEL_PATH, "vectorizer.pkl": VECTORIZER_PATH}
    if not all(name in hashes for name in required):
        return False
    return all(_sha256(path).lower() == hashes[name] for name, path in required.items())


def preprocess(text: Any) -> str:
    """Normalize command text while preserving shell/security signal."""
    if not isinstance(text, str):
        text = str(text)
    text = text.lower().strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[^\w\s\-/\.:;|&$`<>+*]", "", text)
    return text if text else "unknown"


def reset_model_cache():
    """Clear cached artifacts. Primarily useful for tests and retraining flows."""
    global _classifier, _vectorizer, _load_error
    _classifier = None
    _vectorizer = None
    _load_error = None


def _load() -> bool:
    """Load classifier/vectorizer once. Return False instead of raising."""
    global _classifier, _vectorizer, _load_error

    if _classifier is not None and _vectorizer is not None:
        return True

    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        _load_error = "missing_model_artifact"
        return False
    try:
        if not _artifacts_verified():
            _load_error = "artifact_hash_mismatch"
            return False
    except Exception:
        _load_error = "artifact_hash_mismatch"
        return False

    try:
        with open(MODEL_PATH, "rb") as f:
            classifier = pickle.load(f)
        with open(VECTORIZER_PATH, "rb") as f:
            vectorizer = pickle.load(f)
    except Exception as exc:  # fail closed; never break honeypot capture
        _classifier = None
        _vectorizer = None
        _load_error = f"load_failed:{exc.__class__.__name__}"
        return False

    _classifier = classifier
    _vectorizer = vectorizer
    _load_error = None
    return True


def model_status() -> dict:
    """Return lightweight health details for diagnostics/UI/tests."""
    loaded = _load()
    return {
        "loaded": loaded,
        "model_path": MODEL_PATH,
        "vectorizer_path": VECTORIZER_PATH,
        "manifest_path": MANIFEST_PATH,
        "manifest_exists": os.path.exists(MANIFEST_PATH),
        "model_exists": os.path.exists(MODEL_PATH),
        "vectorizer_exists": os.path.exists(VECTORIZER_PATH),
        "error": _load_error,
    }


def predict(command: Any, default: str = "Unknown") -> str:
    """Predict attack category for a command.

    Returns default when the model cannot be loaded or prediction fails.
    """
    details = predict_details(command, default=default)
    return details["attack_category"]


def predict_details(command: Any, default: str = "Unknown") -> dict:
    """Predict category plus confidence/diagnostic metadata."""
    clean = preprocess(command)
    if not _load():
        return {
            "attack_category": default,
            "confidence": None,
            "model_loaded": False,
            "error": _load_error,
            "command_clean": clean,
        }

    try:
        classifier = _classifier
        vectorizer = _vectorizer
        if classifier is None or vectorizer is None:
            raise RuntimeError("model cache not initialized")

        vec = vectorizer.transform([clean])
        category = classifier.predict(vec)[0]
        confidence = None
        if hasattr(classifier, "predict_proba") and hasattr(classifier, "classes_"):
            probabilities = classifier.predict_proba(vec)[0]
            confidence = float(max(probabilities)) if len(probabilities) else None
        return {
            "attack_category": str(category),
            "confidence": confidence,
            "model_loaded": True,
            "error": None,
            "command_clean": clean,
        }
    except Exception as exc:  # fail closed on bad payload/model incompatibility
        return {
            "attack_category": default,
            "confidence": None,
            "model_loaded": True,
            "error": f"predict_failed:{exc.__class__.__name__}",
            "command_clean": clean,
        }
