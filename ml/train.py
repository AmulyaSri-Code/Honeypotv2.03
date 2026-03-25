"""
Train attack classifier: TF-IDF (char w/b only) + Random Forest.
Creates model.pkl and vectorizer.pkl for real-time prediction.
"""
import os
import pickle
import re

try:
    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
except ImportError as e:
    print("Install: pip install pandas scikit-learn")
    raise SystemExit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(SCRIPT_DIR, "dataset.csv")
MODEL_PATH = os.path.join(SCRIPT_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(SCRIPT_DIR, "vectorizer.pkl")

def preprocess(text):
    """Clean command: lowercase, collapse whitespace, keep key chars."""
    if not isinstance(text, str):
        text = str(text)
    text = text.lower().strip()
    text = re.sub(r'\s+', ' ', text)
    # Keeping more characters relevant to shell payload execution
    text = re.sub(r'[^\w\s\-/\.:;|&$`<>+*]', '', text)
    return text

def main():
    print("[*] Loading and expanding dataset...")
    df = pd.read_csv(DATASET)
    df = df.dropna(subset=["command", "attack_category"])
    df["command_clean"] = df["command"].apply(preprocess)
    df = df[df["command_clean"].str.len() > 0]

    X = df["command_clean"]
    y = df["attack_category"]

    print("[*] Training TF-IDF Vectorizer...")
    # Leveraging char_wb (character ngrams inside word boundaries) to catch obfuscated strings
    vectorizer = TfidfVectorizer(
        max_features=500,
        ngram_range=(1, 4),
        min_df=1,
        sublinear_tf=True,
        analyzer="char_wb"
    )
    X_vec = vectorizer.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.15, random_state=42, stratify=y)

    print("[*] Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=None, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n===============================")
    print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
    print("===============================\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))

    # Save models
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(VECTORIZER_PATH, "wb") as f:
        pickle.dump(vectorizer, f)
    print(f"\n[+] Successfully saved {MODEL_PATH}")
    print(f"[+] Successfully saved {VECTORIZER_PATH}")
    print("[+] Model is tied to your current environment package versions. May trigger InconsistentVersionWarning if loaded on different sklearn versions.")

if __name__ == "__main__":
    main()
