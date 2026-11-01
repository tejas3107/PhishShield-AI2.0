import pandas as pd
import joblib

from pathlib import Path
from urllib.parse import urlparse

from url_features import extract_features

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# =====================================
# PROJECT PATHS
# =====================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_PATH = BASE_DIR / "data" / "urls.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"

MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)


# =====================================
# LOAD DATASET
# =====================================

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

df = df.dropna(subset=["url", "label"]).copy()

df["url"] = df["url"].astype(str).str.strip()
df["label"] = pd.to_numeric(df["label"], errors="coerce")

df = df.dropna(subset=["label"])
df["label"] = df["label"].astype(int)

df = df[df["label"].isin([0, 1])]
df = df.drop_duplicates(subset=["url"])

print("Total URLs:", len(df))

print("\nClass distribution:")
print(df["label"].value_counts())


# =====================================
# EXTRACT DOMAINS
# =====================================

def get_domain(url):

    hostname = urlparse(url).hostname

    if not hostname:
        return None

    return hostname.lower().removeprefix("www.")


df["domain"] = df["url"].apply(get_domain)

df = df.dropna(subset=["domain"]).reset_index(drop=True)


# =====================================
# EXTRACT 25 FEATURES
# =====================================

print("\nExtracting advanced URL features...")

X = df["url"].apply(extract_features).tolist()

y = df["label"]
groups = df["domain"]

print("Features per URL:", len(X[0]))


# =====================================
# DOMAIN-BASED DATA SPLIT
# =====================================

print("\nPreparing training and testing data...")

splitter = GroupShuffleSplit(
    n_splits=50,
    test_size=0.20,
    random_state=42
)

split_found = False

for train_idx, test_idx in splitter.split(X, y, groups):

    if (
        y.iloc[train_idx].nunique() == 2
        and y.iloc[test_idx].nunique() == 2
    ):
        split_found = True
        break

if not split_found:
    raise ValueError(
        "Could not create a domain-separated split "
        "containing both classes."
    )


X_train = [X[i] for i in train_idx]
X_test = [X[i] for i in test_idx]

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))

shared_domains = (
    set(groups.iloc[train_idx])
    & set(groups.iloc[test_idx])
)

print("Shared domains:", len(shared_domains))


# =====================================
# TRAIN RANDOM FOREST
# =====================================

print("\nTraining advanced Random Forest...")

model = RandomForestClassifier(
    n_estimators=300,
    max_features="sqrt",
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)


# =====================================
# EVALUATE MODEL
# =====================================

print("\nEvaluating model...")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\n================================")
print("       MODEL EVALUATION")
print("================================")

print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Phishing"],
        zero_division=0
    )
)

print("\nConfusion Matrix:")

print(confusion_matrix(y_test, predictions))


# =====================================
# FEATURE IMPORTANCE
# =====================================

print("\nTop 10 Important Features:")

feature_names = [
    "URL length",
    "Dot count",
    "Hyphen count",
    "At symbol",
    "Question marks",
    "Equal signs",
    "Slash count",
    "HTTPS",
    "IP address",
    "Port",
    "Domain length",
    "Path length",
    "Query length",
    "Subdomain count",
    "TLD length",
    "Suspicious words",
    "Suspicious TLD",
    "Brand indicators",
    "Encoded characters",
    "Digit ratio",
    "URL entropy",
    "Domain entropy",
    "Punycode",
    "Double slash in path",
    "Repeated characters"
]

importance = sorted(
    zip(feature_names, model.feature_importances_),
    key=lambda item: item[1],
    reverse=True
)

for name, score in importance[:10]:
    print(f"{name}: {score:.4f}")


# =====================================
# SAVE MODEL
# =====================================

joblib.dump(model, MODEL_PATH)

print("\n================================")
print("     TRAINING COMPLETED")
print("================================")

print("\nModel saved at:")
print(MODEL_PATH)

print("\nFeatures used:", len(feature_names))