"""
Real-time attack classifier. Load model once, predict fast for each command.
"""
import os
import pickle
import re

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")
VECTORIZER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectorizer.pkl")

_classifier = None
_vectorizer = None

def preprocess(text):
    if not isinstance(text, str):
        text = str(text)
    text = text.lower().strip()
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'[^\w\s\-/\.:;|&$`]', '', text)
    return text if text else "unknown"

def _load():
    global _classifier, _vectorizer
    if _classifier is None and os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        with open(MODEL_PATH, "rb") as f:
            _classifier = pickle.load(f)
        with open(VECTORIZER_PATH, "rb") as f:
            _vectorizer = pickle.load(f)
    return _classifier is not None

def predict(command):
    """Predict attack category for a command. Returns category or 'Unknown' if model not loaded."""
    if not _load():
        return "Unknown"
    clean = preprocess(command)
    vec = _vectorizer.transform([clean])
    return _classifier.predict(vec)[0]
