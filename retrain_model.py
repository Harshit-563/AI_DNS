#!/usr/bin/env python

import pandas as pd
import numpy as np
import random
from pathlib import Path
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

from data_engg import DomainFeatureExtractor

print("=" * 80)
print("DNS THREAT DETECTION - IMPROVED TRAINING")
print("=" * 80)

extractor = DomainFeatureExtractor()

# ============================================================
# STEP 1: LOAD DATA
# ============================================================
print("\n[1] Loading datasets...")
combined_path = Path("Datasets/dga_data.csv/dga_data.csv")
combined_df = pd.read_csv(combined_path)

benign_domains = (
    combined_df.loc[combined_df["isDGA"].astype(str).str.lower() == "legit", "host"]
    .dropna()
    .astype(str)
    .str.strip()
    .unique()
    .tolist()
)
dga_domains = (
    combined_df.loc[combined_df["isDGA"].astype(str).str.lower() == "dga", "host"]
    .dropna()
    .astype(str)
    .str.strip()
    .unique()
    .tolist()
)

random.shuffle(benign_domains)
random.shuffle(dga_domains)

print(f"    Benign domains: {len(benign_domains)}")
print(f"    DGA domains: {len(dga_domains)}")

# ============================================================
# STEP 2: SAMPLE DATA (RANDOMIZED)
# ============================================================
print("\n[2] Sampling data...")

N = min(len(benign_domains), len(dga_domains), 5000)

benign_sample = benign_domains[:N]
dga_sample = dga_domains[:N]

print(f"    Using {N} benign + {N} DGA")

# ============================================================
# STEP 3: FEATURE EXTRACTION
# ============================================================
print("\n[3] Extracting features...")

X, y = [], []

def process(domains, label):
    for i, domain in enumerate(domains):
        if i % 500 == 0:
            print(f"    Progress: {i}/{len(domains)}")
        try:
            features = extractor.extract_all_features(domain)
            X.append(features)
            y.append(label)
        except:
            continue

process(benign_sample, 0)
process(dga_sample, 1)

X = pd.DataFrame(X)
y = pd.Series(y)

print(f"    Total samples: {len(X)}")

# ============================================================
# STEP 4: TRAIN / TEST SPLIT
# ============================================================
print("\n[4] Splitting data...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

# ============================================================
# STEP 5: SCALING
# ============================================================
print("\n[5] Scaling...")

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# ============================================================
# STEP 6: MODEL TRAINING
# ============================================================
print("\n[6] Training model...")

model = RandomForestClassifier(
    n_estimators=150,
    max_depth=15,
    min_samples_leaf=3,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# ============================================================
# STEP 7: EVALUATION (REAL METRICS)
# ============================================================
print("\n[7] Evaluating model...")

y_pred = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# ============================================================
# STEP 8: FEATURE IMPORTANCE
# ============================================================
print("\n[8] Feature Importance:")

feature_names = list(X.columns)
importances = model.feature_importances_

for f, imp in sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True):
    print(f"{f}: {imp:.4f}")

# ============================================================
# STEP 9: SAVE MODEL
# ============================================================
print("\n[9] Saving model...")

artifact = {
    "model": model,
    "scaler": scaler,
    "features": feature_names
}

Path("models").mkdir(exist_ok=True)
joblib.dump(artifact, "models/dns_model_v2.pkl")

print("    Model saved: models/dns_model_v2.pkl")

# ============================================================
# STEP 10: REALITY TEST (IMPORTANT)
# ============================================================
print("\n[10] Testing on real domains...")

test_domains = [
    "google.com",
    "facebook.com",
    "api.amazonaws.com",
    "cdn.cloudflare.net",
    "ajdkslqwe.biz",
    "xj92kdlp.net"
]

for d in test_domains:
    try:
        feat = extractor.extract_all_features(d)
        df = pd.DataFrame([feat])[feature_names]
        df = scaler.transform(df)

        pred = model.predict(df)[0]
        label = "Benign" if pred == 0 else "DGA"

        print(f"{d:25s} → {label}")
    except Exception as e:
        print(f"{d:25s} → ERROR")
