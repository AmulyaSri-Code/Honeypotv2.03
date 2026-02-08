"""
Train attack classifier: TF-IDF + Logistic Regression.
Creates model.pkl and vectorizer.pkl for real-time prediction.
"""
import os
import pickle
import re

try:
    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
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
    text = re.sub(r'[^\w\s\-/\.:;|&$`]', '', text)
    return text

def main():
    df = pd.read_csv(DATASET)
    df = df.dropna(subset=["command", "attack_category"])
    df["command_clean"] = df["command"].apply(preprocess)
    df = df[df["command_clean"].str.len() > 0]

    X = df["command_clean"]
    y = df["attack_category"]

    vectorizer = TfidfVectorizer(
        max_features=300,
        ngram_range=(1, 2),
        min_df=1,
        sublinear_tf=True,
        analyzer="word",
        token_pattern=r"\b[\w/\.\-]+\b",
    )
    X_vec = vectorizer.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.15, random_state=42, stratify=y)

    model = LogisticRegression(max_iter=500, C=1.0, solver="lbfgs", random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(VECTORIZER_PATH, "wb") as f:
        pickle.dump(vectorizer, f)
    print(f"\nSaved {MODEL_PATH} and {VECTORIZER_PATH}")

if __name__ == "__main__":
    main()
