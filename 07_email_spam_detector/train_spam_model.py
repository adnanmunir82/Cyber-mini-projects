import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import json

DATASET_PATH = "sms_spam.tsv"
MODEL_PATH = "spam_model.joblib"
VECTORIZER_PATH = "vectorizer.joblib"
METRICS_PATH = "model_metrics.json"


def train_and_evaluate():
    df = pd.read_csv(DATASET_PATH, sep="\t", header=None, names=["label", "message"])
    df = df.dropna()

    X = df["message"]
    y = df["label"].map({"ham": 0, "spam": 1})

    # 80/20 train/test split, stratified to preserve the real spam/ham ratio in both sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    vectorizer = TfidfVectorizer(stop_words="english", max_features=5000, ngram_range=(1, 2), lowercase=True)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = MultinomialNB(alpha=0.1)
    model.fit(X_train_vec, y_train)

    predictions = model.predict(X_test_vec)

    metrics = {
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(y_test, predictions),
        "recall": recall_score(y_test, predictions),
        "f1_score": f1_score(y_test, predictions),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "spam_in_test": int(y_test.sum()),
        "ham_in_test": int((y_test == 0).sum()),
    }

    cm = confusion_matrix(y_test, predictions)
    metrics["confusion_matrix"] = cm.tolist()  # [[TN, FP], [FN, TP]]

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    return metrics


if __name__ == "__main__":
    metrics = train_and_evaluate()
    print("Training complete.")
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1 Score:  {metrics['f1_score']:.4f}")
    print(f"Confusion Matrix (TN, FP / FN, TP): {metrics['confusion_matrix']}")