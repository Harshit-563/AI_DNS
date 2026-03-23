import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from Analysis import build_default_analyzer
from data_engg import extractor


class DatasetBuilder:
    """Build complete training dataset."""

    def __init__(self, benign_domains, malicious_domains, feature_extractor):
        self.benign_domains = benign_domains
        self.malicious_domains = malicious_domains
        self.feature_extractor = feature_extractor
        self.dataset = None
        self.X = None
        self.y = None
        self.scaler = None

    def build_dataset(self, max_samples_per_class=None):
        """Build dataset with features and labels."""
        print("\n" + "=" * 60)
        print("BUILDING DATASET")
        print("=" * 60)

        benign = self.benign_domains
        malicious = self.malicious_domains

        if max_samples_per_class:
            benign = benign[:max_samples_per_class]
            malicious = malicious[:max_samples_per_class]

        all_data = []

        print(f"\nProcessing {len(benign)} benign domains...")
        for i, domain in enumerate(benign):
            if (i + 1) % 10000 == 0:
                print(f"  {i + 1}/{len(benign)}")
            try:
                features = self.feature_extractor.extract_all_features(domain)
                features["domain"] = domain
                features["label"] = 0
                all_data.append(features)
            except Exception as e:
                print(f"  [ERROR] Error processing {domain}: {e}")

        print(f"\nProcessing {len(malicious)} malicious domains...")
        for i, domain in enumerate(malicious):
            if (i + 1) % 10000 == 0:
                print(f"  {i + 1}/{len(malicious)}")
            try:
                features = self.feature_extractor.extract_all_features(domain)
                features["domain"] = domain
                features["label"] = 1
                all_data.append(features)
            except Exception as e:
                print(f"  [ERROR] Error processing {domain}: {e}")

        self.dataset = pd.DataFrame(all_data)
        print(f"\n[OK] Created dataset with {len(self.dataset)} samples")
        self._print_stats()
        return self.dataset

    def _print_stats(self):
        """Print dataset statistics."""
        benign_count = (self.dataset["label"] == 0).sum()
        malicious_count = (self.dataset["label"] == 1).sum()
        balance = benign_count / max(malicious_count, 1)

        print("\nDataset Statistics:")
        print(f"  Total samples: {len(self.dataset)}")
        print(f"  Benign: {benign_count}")
        print(f"  Malicious: {malicious_count}")
        print(f"  Class balance: {balance:.2f}:1")
        print(f"  Features: {len([c for c in self.dataset.columns if c not in ['domain', 'label']])}")

    def handle_class_imbalance(self, method="undersample"):
        """Handle class imbalance."""
        if method == "undersample":
            benign_count = (self.dataset["label"] == 0).sum()
            malicious_count = (self.dataset["label"] == 1).sum()

            if benign_count > malicious_count and malicious_count > 0:
                benign_samples = self.dataset[self.dataset["label"] == 0].sample(
                    n=malicious_count,
                    random_state=42,
                )
                malicious_samples = self.dataset[self.dataset["label"] == 1]
                self.dataset = pd.concat([benign_samples, malicious_samples]).reset_index(drop=True)

            print(f"[OK] Undersampled dataset: {len(self.dataset)} samples")

        elif method == "oversample":
            from sklearn.utils import resample

            benign = self.dataset[self.dataset["label"] == 0]
            malicious = self.dataset[self.dataset["label"] == 1]

            if len(benign) > len(malicious) and len(malicious) > 0:
                malicious = resample(malicious, n_samples=len(benign), random_state=42)
            elif len(benign) > 0:
                benign = resample(benign, n_samples=len(malicious), random_state=42)

            self.dataset = pd.concat([benign, malicious]).reset_index(drop=True)
            print(f"[OK] Oversampled dataset: {len(self.dataset)} samples")

    def prepare_features(self, test_size=0.2, scale=True):
        """Prepare X and y for training."""
        feature_cols = [c for c in self.dataset.columns if c not in ["domain", "label"]]
        self.X = self.dataset[feature_cols].fillna(0)
        self.y = self.dataset["label"]

        X_train, X_test, y_train, y_test = train_test_split(
            self.X,
            self.y,
            test_size=test_size,
            random_state=42,
            stratify=self.y,
        )

        if scale:
            scaler = StandardScaler()
            X_train = pd.DataFrame(scaler.fit_transform(X_train), columns=feature_cols, index=X_train.index)
            X_test = pd.DataFrame(scaler.transform(X_test), columns=feature_cols, index=X_test.index)
            self.scaler = scaler
        else:
            self.scaler = None

        print(f"\n[OK] Train set: {len(X_train)} samples")
        print(f"[OK] Test set: {len(X_test)} samples")
        return X_train, X_test, y_train, y_test

    def save_dataset(self, filepath):
        """Save dataset to CSV."""
        self.dataset.to_csv(filepath, index=False)
        print(f"[OK] Dataset saved to {filepath}")

    def get_feature_importance_baseline(self):
        """Get baseline feature importance."""
        return list(self.X.columns)


if __name__ == "__main__":
    analyzer = build_default_analyzer()
    dataset_builder = DatasetBuilder(
        analyzer.benign_domains,
        analyzer.malicious_domains,
        extractor,
    )

    dataset = dataset_builder.build_dataset(max_samples_per_class=50000)
    dataset_builder.handle_class_imbalance(method="undersample")
    X_train, X_test, y_train, y_test = dataset_builder.prepare_features(test_size=0.2)
    dataset_builder.save_dataset("dns_threat_dataset.csv")

    print("\n" + "=" * 60)
    print("DATASET SAMPLE")
    print("=" * 60)
    print(dataset.head(3))
