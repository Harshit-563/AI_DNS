"""
Fast Flux Detection Integration Example
Demonstrates how to use FastFluxDetector with your existing 7-feature model
"""

import pandas as pd
import numpy as np
from pathlib import Path
import warnings

# Import from your modules
from data_engg import DomainFeatureExtractor, FastFluxDetector

class IntegratedThreatClassifier:
    """
    Combines your 7-feature model with Fast Flux detection
    For 4-class classification: Benign (0), DGA (1), Fast-Flux (2), Suspicious (3)
    """
    
    def __init__(self, model_path=None):
        """Initialize classifier with optional pretrained model"""
        self.extractor = DomainFeatureExtractor()
        self.ff_detector = FastFluxDetector()
        
        # Optional: Load your trained model
        self.model = None
        self.feature_columns = None
        self.scaler = None
        if model_path:
            model_file = Path(model_path)
            if not model_file.exists():
                raise FileNotFoundError(f"Model file not found: {model_file}")

            import joblib
            loaded_artifact = joblib.load(model_file)

            if isinstance(loaded_artifact, dict) and "model" in loaded_artifact:
                self.model = loaded_artifact["model"]
                # Try both 'feature_columns' and 'features' keys for compatibility
                self.feature_columns = loaded_artifact.get("feature_columns") or loaded_artifact.get("features")
                self.scaler = loaded_artifact.get("scaler")
            else:
                self.model = loaded_artifact
    
    def extract_7_features(self, domain, ttl, unique_ip_count, query_rate):
        """
        Extract the 7 original features for your trained model
        Maps comprehensive extractor output to original 7 features
        """
        all_features = self.extractor.extract_all_features(domain)
        
        feature_vector = {
            'domain': domain,  # Add domain for benign pattern matching
            'domain_length': all_features['domain_length'],
            'entropy': all_features['character_entropy'],  # Key mapping!
            'digit_ratio': all_features['digit_ratio'],
            'subdomain_depth': all_features['subdomain_depth'],
            'ttl': ttl,
            'unique_ip_count': unique_ip_count,
            'query_rate': query_rate,
            'vowel_count': sum(1 for c in domain.lower() if c in 'aeiou')  # Add vowel count
        }
        
        return feature_vector
    
    def detect_fastflux(self, domain, ttl, unique_ip_count, query_rate):
        """Detect Fast Flux characteristics"""
        return self.ff_detector.compute_fastflux_score(
            domain, ttl, unique_ip_count, query_rate
        )
    
    def classify(self, domain, ttl, unique_ip_count, query_rate, use_fast_flux=True):
        """
        Classify domain into threat category
        
        Args:
            domain: Domain name string
            ttl: TTL value from DNS (seconds)
            unique_ip_count: Count of unique IPs
            query_rate: Query rate metric
            use_fast_flux: Whether to apply FF detection
        
        Returns:
            Classification result dictionary
        """
        
        # Extract 7 features
        features_7 = self.extract_7_features(domain, ttl, unique_ip_count, query_rate)
        all_features = self.extractor.extract_all_features(domain)
        
        # Get base prediction from your trained model
        if self.model:
            feature_array = self._prepare_model_input(all_features, features_7)
            base_prediction = int(self.model.predict(feature_array)[0])
            base_probability = self.model.predict_proba(feature_array)[0]
        else:
            # Fallback heuristic-based classifier when no model is available
            base_prediction, base_probability = self._heuristic_classify(features_7)
        
        # Fast Flux detection
        ff_result = None
        final_class = base_prediction
        confidence = float(base_probability[base_prediction]) if base_probability is not None else 0.5
        
        if use_fast_flux:
            ff_result = self.detect_fastflux(domain, ttl, unique_ip_count, query_rate)
            
            # If FF detected, override classification to class 2 (Fast-Flux)
            if ff_result['is_fastflux'] and ff_result['fastflux_score'] > 0.65:
                final_class = 2  # Fast-Flux class
                confidence = float(ff_result['fastflux_score'])
        
        # Map class to label
        class_labels = {
            0: "Benign",
            1: "DGA",
            2: "Fast-Flux",
            3: "Suspicious"
        }
        
        result = {
            'domain': domain,
            'base_prediction': class_labels.get(base_prediction, 'Unknown'),
            'base_class': int(base_prediction),
            'base_confidence': float(base_probability[base_prediction]) if base_probability is not None else 0.5,
            'final_prediction': class_labels.get(final_class, 'Unknown'),
            'final_class': int(final_class),
            'confidence': float(confidence),
            'features_7': features_7,
            'fastflux_analysis': self._to_native(ff_result) if use_fast_flux else None
        }
        
        return result

    def _to_native(self, value):
        """Convert numpy scalars/containers to JSON-safe Python types."""
        if isinstance(value, dict):
            return {key: self._to_native(val) for key, val in value.items()}
        if isinstance(value, list):
            return [self._to_native(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._to_native(item) for item in value)
        if isinstance(value, np.generic):
            return value.item()
        return value

    def _prepare_model_input(self, all_features, features_7):
        """Build the correct feature array for the loaded model artifact."""
        if self.feature_columns:
            # Build feature array in the correct order
            feature_array = []
            for column in self.feature_columns:
                # Get from all_features dict, default to 0 if missing
                feature_array.append(all_features.get(column, 0))
            
            feature_frame = pd.DataFrame(
                [feature_array],
                columns=self.feature_columns,
            )
            
            # Apply scaler if available
            if self.scaler is not None:
                feature_frame = pd.DataFrame(
                    self.scaler.transform(feature_frame),
                    columns=self.feature_columns,
                )
            return feature_frame

        expected_features = getattr(self.model, "n_features_in_", None)
        if expected_features == 7:
            return np.array([
                features_7['domain_length'],
                features_7['entropy'],
                features_7['digit_ratio'],
                features_7['subdomain_depth'],
                features_7['ttl'],
                features_7['unique_ip_count'],
                features_7['query_rate']
            ]).reshape(1, -1)

        ordered_features = list(all_features.keys())
        if expected_features == len(ordered_features):
            warnings.warn(
                "Loaded model lacks saved feature metadata; using inferred lexical feature order.",
                RuntimeWarning,
            )
            return pd.DataFrame([[all_features[name] for name in ordered_features]], columns=ordered_features)

        raise ValueError(
            f"Unsupported model feature shape: expected {expected_features}, "
            f"available 7 or {len(ordered_features)} features"
        )
    
    def _heuristic_classify(self, features):
        """
        Heuristic-based classifier for when no trained model is available
        Returns (class, probabilities)
        """
        domain_len = features['domain_length']
        entropy = features['entropy']
        digit_ratio = features['digit_ratio']
        subdomain_depth = features['subdomain_depth']
        ttl = features['ttl']
        unique_ips = features['unique_ip_count']
        query_rate = features['query_rate']
        
        # DGA Detection (Domain Generation Algorithm)
        dga_score = 0.0
        
        # High entropy is strongest DGA indicator (>3.2 is suspicious)
        if entropy > 3.2:
            dga_score += 0.4
        elif entropy > 3.0:
            dga_score += 0.3
        elif entropy > 2.8:
            dga_score += 0.2
        
        # Longer random-looking domains are suspicious (10-15 chars typical for DGA)
        if 10 <= domain_len <= 15 and entropy > 2.8:
            dga_score += 0.25
        
        # Mix of consonants/vowels in DGA domains is less balanced
        vowel_count = features.get('vowel_count', 0)
        if domain_len > 5 and vowel_count < domain_len * 0.25:
            dga_score += 0.15
        
        # Low digit ratio with high entropy = DGA
        if digit_ratio < 0.1 and entropy > 3.0:
            dga_score += 0.15
        
        # Fast-Flux indicators
        ff_score = 0.0
        
        # Multiple IPs for single domain
        if unique_ips > 5:
            ff_score += 0.4
        elif unique_ips > 3:
            ff_score += 0.2
        
        # Low TTL with high query rate
        if ttl < 300 and query_rate > 10:
            ff_score += 0.3
        elif ttl < 600 and query_rate > 5:
            ff_score += 0.2
        
        # Many subdomains suspicious
        if subdomain_depth > 2:
            ff_score += 0.1
        
        # General suspicious indicators
        suspicious_score = 0.0
        
        # Very short domains often legitimate (google.com, amazon.com)
        if domain_len < 7:
            suspicious_score -= 0.3
        
        # Benign heuristics - common patterns
        benign_indicators = 0
        domain_lower = features.get('domain', '').lower()
        
        # Known benign patterns
        common_benign = [
            'google', 'facebook', 'twitter', 'amazon', 'microsoft', 
            'apple', 'netflix', 'instagram', 'linkedin', 'youtube',
            'reddit', 'github', 'wikipedia', 'stackoverflow'
        ]
        
        if any(benign in domain_lower for benign in common_benign):
            dga_score -= 0.5
            ff_score -= 0.3
            suspicious_score -= 0.3
        
        # Normalize scores
        dga_score = max(0.0, min(1.0, dga_score))
        ff_score = max(0.0, min(1.0, ff_score))
        suspicious_score = max(0.0, min(0.5, max(0.0, suspicious_score)))
        
        # Decision logic with clear thresholds
        if dga_score > 0.5:  # Strong DGA signal
            prediction = 1
            probs = [0.15, 0.70, 0.10, 0.05]
        elif ff_score > 0.5:  # Strong Fast-Flux signal
            prediction = 2
            probs = [0.10, 0.10, 0.75, 0.05]
        elif dga_score > 0.3:  # Moderate DGA signal
            prediction = 1
            probs = [0.20, 0.55, 0.15, 0.10]
        elif ff_score > 0.3:  # Moderate Fast-Flux signal
            prediction = 2
            probs = [0.15, 0.15, 0.55, 0.15]
        elif (dga_score + ff_score) > 0.4:  # Mixed threat signals
            prediction = 3  # Suspicious
            probs = [0.25, 0.25, 0.25, 0.25]
        else:  # Benign
            prediction = 0
            probs = [0.80, 0.10, 0.05, 0.05]
        
        return prediction, np.array(probs)
    
    def batch_classify(self, domains_df, use_fast_flux=True):
        """
        Classify multiple domains from DataFrame
        
        Args:
            domains_df: DataFrame with columns [domain, ttl, unique_ip_count, query_rate]
            use_fast_flux: Whether to apply FF detection
        
        Returns:
            DataFrame with classifications
        """
        results = []
        
        for idx, row in domains_df.iterrows():
            result = self.classify(
                domain=row['domain'],
                ttl=row.get('ttl', 3600),
                unique_ip_count=row.get('unique_ip_count', 1),
                query_rate=row.get('query_rate', 0),
                use_fast_flux=use_fast_flux
            )
            results.append(result)
        
        # Convert to DataFrame for easy analysis
        output_df = pd.DataFrame(results)
        return output_df


# ============================================================
# EXAMPLE USAGE
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("INTEGRATED THREAT CLASSIFIER - FAST FLUX DETECTION")
    print("=" * 70)
    
    # Initialize classifier
    classifier = IntegratedThreatClassifier()
    
    # Test cases with network data
    test_cases = [
        {
            'domain': 'google.com',
            'ttl': 3600,
            'unique_ip_count': 1,
            'query_rate': 50000,
            'expected': 'Benign'
        },
        {
            'domain': 'asdflkjhwerty.xyz',
            'ttl': 300,
            'unique_ip_count': 2,
            'query_rate': 100,
            'expected': 'DGA'
        },
        {
            'domain': 'sub1.sub2.malware-flux.net',
            'ttl': 60,
            'unique_ip_count': 12,
            'query_rate': 2000,
            'expected': 'Fast-Flux'
        },
        {
            'domain': 'phishing-site.ru',
            'ttl': 1800,
            'unique_ip_count': 3,
            'query_rate': 500,
            'expected': 'Suspicious'
        },
    ]
    
    print("\n1. SINGLE DOMAIN CLASSIFICATION")
    print("-" * 70)
    
    for test in test_cases:
        result = classifier.classify(
            domain=test['domain'],
            ttl=test['ttl'],
            unique_ip_count=test['unique_ip_count'],
            query_rate=test['query_rate'],
            use_fast_flux=True
        )
        
        print(f"\nDomain: {result['domain']}")
        print(f"  Expected: {test['expected']}")
        print(f"  Final Prediction: {result['final_prediction']}")
        print(f"  Confidence: {result['base_confidence']:.2f}" if result['base_confidence'] else "  Confidence: N/A")
        
        if result['fastflux_analysis']:
            ff = result['fastflux_analysis']
            print(f"  Fast Flux Score: {ff['fastflux_score']:.3f}")
            print(f"    ├─ Domain Lexical: {ff['domain_lexical_score']:.3f}")
            print(f"    ├─ Subdomain Complexity: {ff['subdomain_complexity_score']:.3f}")
            print(f"    ├─ Domain Age: {ff['domain_age_score']:.3f}")
            print(f"    ├─ TTL Vulnerability: {ff['ttl_score']:.3f}")
            print(f"    ├─ IP Diversity: {ff['ip_diversity_score']:.3f}")
            print(f"    └─ Query Rate Anomaly: {ff['query_rate_score']:.3f}")
    
    # Batch classification example
    print("\n\n2. BATCH CLASSIFICATION FROM DATAFRAME")
    print("-" * 70)
    
    # Create sample DataFrame
    domains_data = {
        'domain': [
            'example.com',
            'generated-dga.tk',
            'botnet-ff.cc',
            'suspicious.ru'
        ],
        'ttl': [3600, 300, 60, 1800],
        'unique_ip_count': [1, 1, 10, 3],
        'query_rate': [1000, 50, 5000, 500]
    }
    
    df = pd.DataFrame(domains_data)
    results_df = classifier.batch_classify(df, use_fast_flux=True)
    
    print("\nBatch Results:")
    print(results_df[['domain', 'base_prediction', 'final_prediction', 'final_class']].to_string(index=False))
    
    # Distribution analysis
    print("\n\nFinal Classification Distribution:")
    print(results_df['final_prediction'].value_counts())
    
    # Show Fast Flux scores for all
    print("\n\nFast Flux Scores for All Domains:")
    for idx, row in results_df.iterrows():
        ff = row['fastflux_analysis']
        if ff:
            print(f"{row['domain']:20s} → FF Score: {ff['fastflux_score']:.3f} | "
                  f"FF?: {'YES' if ff['is_fastflux'] else 'NO '}")


# ============================================================
# INTEGRATION WITH YOUR PIPELINE
# ============================================================

"""
To use in your existing pipeline:

1. In your data preprocessing (Analysis.py):
   
   classifier = IntegratedThreatClassifier(model_path="dns_rf_model.pkl")
   
   # When processing domains:
   result = classifier.classify(
       domain=domain_name,
       ttl=dns_ttl_value,
       unique_ip_count=count_of_ips,
       query_rate=query_metrics
   )
   
   # Get final threat class
   threat_class = result['final_class']  # 0, 1, 2, or 3


2. In your app.py or main.py:
   
   results_df = classifier.batch_classify(domains_dataframe)
   
   # Save enhanced dataset with FF detection
   results_df.to_csv('classified_domains_with_ff.csv', index=False)


3. For API responses:
   
   @app.post("/classify")
   def classify_endpoint(domain: str, network_data: dict):
       result = classifier.classify(
           domain=domain,
           ttl=network_data['ttl'],
           unique_ip_count=network_data['unique_ips'],
           query_rate=network_data['query_rate']
       )
       return result


That's it! Your 7-feature model + Fast Flux detection = 4-class classification
"""
