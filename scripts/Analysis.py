import pandas as pd
import numpy as np
from collections import Counter
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
BENIGN_DATA_DIR = BASE_DIR / 'Datasets' / 'Bengin'
DGA_DATA_DIR = BASE_DIR / 'Datasets' / 'DGA'
COMBINED_DGA_DATA_PATH = BASE_DIR / 'Datasets' / 'dga_data.csv' / 'dga_data.csv'


class DatasetAnalyzer:
    def __init__(self):
        self.benign_domains = []
        self.malicious_domains = []
        self.multi_part_suffixes = {
            'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
            'com.au', 'net.au', 'org.au',
            'co.in', 'org.in', 'net.in',
            'com.br', 'com.mx',
        }

    def load_tranco(self, file_path):
        """Load Tranco top 1M domains."""
        try:
            file_path = Path(file_path)
            df = pd.read_csv(file_path, compression='gzip' if file_path.suffix == '.gz' else None)
            domains = df.iloc[:, 1].tolist() if df.shape[1] > 1 else df.iloc[:, 0].tolist()
            self.benign_domains.extend(domains)
            print(f"[OK] Loaded {len(domains)} Tranco domains")
        except Exception as e:
            print(f"[ERROR] Error loading Tranco: {e}")

    def load_text_domains(self, file_path, label='benign'):
        try:
            file_path = Path(file_path)
            with file_path.open('r', encoding='utf-8') as f:
                domains = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith('//')
                ]

            if label == 'benign':
                self.benign_domains.extend(domains)
            else:
                self.malicious_domains.extend(domains)

            print(f"[OK] Loaded {len(domains)} {label} domains from {file_path}")
        except Exception as e:
            print(f"[ERROR] Error loading {file_path}: {e}")

    def load_csv_domains(self, file_path, domain_column='domain', label='malicious', class_column=None, class_value=None):
        try:
            file_path = Path(file_path)
            df = pd.read_csv(file_path)

            if class_column and class_value is not None and class_column in df.columns:
                df = df[df[class_column].astype(str).str.lower() == str(class_value).lower()]

            if domain_column not in df.columns:
                raise ValueError(f"Missing '{domain_column}' column in {file_path}")

            domains = df[domain_column].dropna().astype(str).str.strip().tolist()

            if label == 'benign':
                self.benign_domains.extend(domains)
            else:
                self.malicious_domains.extend(domains)

            print(f"[OK] Loaded {len(domains)} {label} domains from {file_path}")
        except Exception as e:
            print(f"[ERROR] Error loading {file_path}: {e}")

    def clean_domains(self):
        """Clean and validate domains."""

        def is_valid_domain(domain):
            pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$'
            return re.match(pattern, domain) is not None and 0 < len(domain) < 253

        self.benign_domains = list(set([d.lower() for d in self.benign_domains if is_valid_domain(d.lower())]))
        self.malicious_domains = list(set([d.lower() for d in self.malicious_domains if is_valid_domain(d.lower())]))

        print(f"[OK] After cleaning: {len(self.benign_domains)} benign, {len(self.malicious_domains)} malicious")

    def extract_core_domain(self, domain):
        """Normalize a domain to a comparable core label."""
        parts = domain.lower().strip().split('.')

        if len(parts) == 1:
            return parts[0]

        suffix = '.'.join(parts[-2:])
        if len(parts) >= 3 and suffix in self.multi_part_suffixes:
            return parts[-3]

        return parts[-2]

    def normalize_domain_representation(self):
        """Reduce both classes to the same lexical level."""
        self.benign_domains = [self.extract_core_domain(domain) for domain in self.benign_domains]
        self.malicious_domains = [self.extract_core_domain(domain) for domain in self.malicious_domains]
        print("[OK] Normalized both classes to core-domain representation")

    def remove_duplicates_across_sets(self):
        """Remove any domains that appear in both sets."""
        overlap = set(self.benign_domains) & set(self.malicious_domains)

        if overlap:
            self.malicious_domains = [d for d in self.malicious_domains if d not in overlap]
            print(f"[WARN] Removed {len(overlap)} overlapping domains")

    def get_stats(self):
        """Print dataset statistics."""
        print("\n" + "=" * 60)
        print("DATASET STATISTICS")
        print("=" * 60)
        print(f"Benign domains: {len(self.benign_domains)}")
        print(f"Malicious domains: {len(self.malicious_domains)}")
        print(f"Total domains: {len(self.benign_domains) + len(self.malicious_domains)}")
        print(f"Class balance ratio: 1:{len(self.benign_domains) / max(len(self.malicious_domains), 1):.2f}")
        print("=" * 60 + "\n")


def build_default_analyzer():
    analyzer = DatasetAnalyzer()
    analyzer.load_csv_domains(
        COMBINED_DGA_DATA_PATH,
        domain_column='host',
        label='benign',
        class_column='isDGA',
        class_value='legit',
    )
    analyzer.load_csv_domains(
        COMBINED_DGA_DATA_PATH,
        domain_column='host',
        label='malicious',
        class_column='isDGA',
        class_value='dga',
    )
    analyzer.clean_domains()
    analyzer.remove_duplicates_across_sets()
    return analyzer


if __name__ == "__main__":
    analyzer = build_default_analyzer()
    analyzer.get_stats()
