"""
How to Add Fast Flux Detection to Your Current Pipeline
Minimal changes needed - drop-in integration
"""

import pandas as pd
from pathlib import Path
from data_engg import DomainFeatureExtractor, FastFluxDetector
# from ai_model import DNSThreatDetector  # Your existing model

class EnhancedDomainClassifier:
    """
    Your existing pipeline + Fast Flux detection
    Minimal changes to your current code
    """
    
    def __init__(self):
        self.extractor = DomainFeatureExtractor()
        self.ff_detector = FastFluxDetector()
        # self.model = DNSThreatDetector()  # Uncomment if you have trained model
    
    def get_7_features(self, domain, ttl, unique_ip_count, query_rate):
        """
        Extract your original 7 features
        Maps: entropy = character_entropy
        """
        all_features = self.extractor.extract_all_features(domain)
        
        return [
            all_features['domain_length'],
            all_features['character_entropy'],  # ← entropy
            all_features['digit_ratio'],
            all_features['subdomain_depth'],
            ttl,
            unique_ip_count,
            query_rate
        ]
    
    def classify(self, domain, ttl, unique_ip_count, query_rate):
        """
        Simple classification with Fast Flux detection
        """
        # Get 7-feature classification (if model available)
        feature_vector = self.get_7_features(
            domain, ttl, unique_ip_count, query_rate
        )
        
        # TODO: Uncomment if you have model loaded
        # base_class = self.model.predict([feature_vector])[0]
        base_class = None
        
        # Add Fast Flux detection
        ff_result = self.ff_detector.compute_fastflux_score(
            domain, ttl, unique_ip_count, query_rate
        )
        
        # Determine final class
        final_class = base_class
        if ff_result['is_fastflux']:
            final_class = 2  # Fast-Flux class
        
        return {
            'domain': domain,
            'base_class': base_class,
            'final_class': final_class,
            'ff_score': ff_result['fastflux_score'],
            'is_fastflux': ff_result['is_fastflux'],
            'details': ff_result
        }


# ============================================================
# EXAMPLE: PROCESS YOUR CSV DATASET
# ============================================================

def process_domains_csv(input_csv, output_csv=None):
    """
    Read domains from CSV and add Fast Flux detection
    Same as your current pipeline, just adds FF detection
    """
    classifier = EnhancedDomainClassifier()
    
    # Read your domains
    df = pd.read_csv(input_csv)
    print(f"Loaded {len(df)} domains from {input_csv}")
    
    # Process each domain
    results = []
    for idx, row in df.iterrows():
        if idx % 100 == 0:
            print(f"Processing {idx}...")
        
        result = classifier.classify(
            domain=row.get('domain'),
            ttl=row.get('ttl', 3600),
            unique_ip_count=row.get('unique_ip_count', 1),
            query_rate=row.get('query_rate', 0)
        )
        results.append(result)
    
    # Convert to DataFrame
    result_df = pd.DataFrame(results)
    
    # Save output
    if output_csv is None:
        output_csv = input_csv.replace('.csv', '_with_ff.csv')
    
    result_df.to_csv(output_csv, index=False)
    print(f"\nSaved results to {output_csv}")
    
    # Show summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Total domains: {len(result_df)}")
    print(f"\nFast Flux Distribution:")
    print(result_df['is_fastflux'].value_counts())
    print(f"\nAverage FF Score: {result_df['ff_score'].mean():.3f}")
    print(f"Domains with FF Score > 0.6: {(result_df['ff_score'] > 0.6).sum()}")
    
    return result_df


# ============================================================
# EXAMPLE: DIRECTLY IN YOUR ANALYSIS.py
# ============================================================

"""
To integrate into your existing Analysis.py:

from data_engg import FastFluxDetector

class DatasetAnalyzer:  # Your existing class
    
    def __init__(self):
        # ... your existing code ...
        self.ff_detector = FastFluxDetector()
    
    def extract_features(self, domain, network_data):
        \"\"\"Add to your existing feature extraction\"\"\"
        features = {}
        
        # ... your existing 7 features ...
        features['domain_length'] = len(domain)
        features['entropy'] = self.calculate_entropy(domain)
        # etc...
        
        # NEW: Add Fast Flux detection
        ff_result = self.ff_detector.compute_fastflux_score(
            domain=domain,
            ttl=network_data.get('ttl'),
            unique_ip_count=network_data.get('unique_ip_count'),
            query_rate=network_data.get('query_rate')
        )
        features['fastflux_score'] = ff_result['fastflux_score']
        features['is_fastflux'] = ff_result['is_fastflux']
        
        return features
"""


# ============================================================
# EXAMPLE: TESTING
# ============================================================

if __name__ == "__main__":
    print("="*70)
    print("FAST FLUX DETECTION - IMPLEMENTATION EXAMPLE")
    print("="*70)
    
    classifier = EnhancedDomainClassifier()
    
    # Test with sample domains
    samples = [
        {
            'name': 'Google',
            'domain': 'google.com',
            'ttl': 3600,
            'ips': 1,
            'rate': 50000
        },
        {
            'name': 'DGA-Generated',
            'domain': 'qwerty123.tk',
            'ttl': 300,
            'ips': 2,
            'rate': 100
        },
        {
            'name': 'Fast Flux Network',
            'domain': 'malware.cc',
            'ttl': 60,
            'ips': 12,
            'rate': 5000
        },
        {
            'name': 'Phishing Site',
            'domain': 'paypal-verify.ru',
            'ttl': 1800,
            'ips': 3,
            'rate': 200
        }
    ]
    
    print("\n" + "=" * 70)
    print("CLASSIFICATION RESULTS")
    print("=" * 70)
    
    for sample in samples:
        result = classifier.classify(
            domain=sample['domain'],
            ttl=sample['ttl'],
            unique_ip_count=sample['ips'],
            query_rate=sample['rate']
        )
        
        ff = result['details']
        
        print(f"\n{sample['name']:20s} ({sample['domain']})")
        print(f"  Network Settings:")
        print(f"    - TTL: {sample['ttl']}s")
        print(f"    - Unique IPs: {sample['ips']}")
        print(f"    - Query Rate: {sample['rate']}")
        
        print(f"  Detection Results:")
        print(f"    - Fast Flux Score: {ff['fastflux_score']:.3f}")
        print(f"    - Is Fast Flux: {'✓ YES' if ff['is_fastflux'] else '✗ NO'}")
        
        print(f"  Score Breakdown:")
        print(f"    - Domain Lexical: {ff['domain_lexical_score']:.3f}")
        print(f"    - Subdomain Complexity: {ff['subdomain_complexity_score']:.3f}")
        print(f"    - Domain Age: {ff['domain_age_score']:.3f}")
        print(f"    - TTL Vulnerability: {ff['ttl_score']:.3f}")
        print(f"    - IP Diversity: {ff['ip_diversity_score']:.3f}")
        print(f"    - Query Rate Anomaly: {ff['query_rate_score']:.3f}")
    
    # Example: Process from CSV
    print("\n\n" + "=" * 70)
    print("BATCH PROCESSING EXAMPLE")
    print("=" * 70)
    
    # Create sample CSV
    sample_data = {
        'domain': ['example.com', 'botnet.cc', 'google.com', 'malware.ru'],
        'ttl': [3600, 60, 3600, 300],
        'unique_ip_count': [1, 10, 1, 5],
        'query_rate': [1000, 2000, 50000, 500]
    }
    
    df = pd.DataFrame(sample_data)
    df.to_csv('sample_domains.csv', index=False)
    print("Created sample_domains.csv")
    
    # Process it
    result_df = process_domains_csv('sample_domains.csv', 'sample_domains_with_ff.csv')
    
    print("\nOutput Preview:")
    print(result_df[['domain', 'ff_score', 'is_fastflux']].to_string(index=False))
    
    # Cleanup
    Path('sample_domains.csv').unlink(missing_ok=True)


# ============================================================
# HOW TO USE IN YOUR ACTUAL CODE
# ============================================================

"""
STEP 1: Import in your main pipeline
    from data_engg import FastFluxDetector
    ff_detector = FastFluxDetector()

STEP 2: When processing each domain, add:
    ff_result = ff_detector.compute_fastflux_score(
        domain=domain_name,
        ttl=ttl_value,
        unique_ip_count=num_ips,
        query_rate=query_rate
    )

STEP 3: Store the result:
    dataset['fastflux_score'] = ff_result['fastflux_score']
    dataset['classification'] = 2 if ff_result['is_fastflux'] else 1  # or 0, 3

STEP 4: That's it! No retraining needed.

Full example in current code:
    
    # In Analysis.py or wherever you process domains:
    
    for domain in domain_list:
        ff_result = ff_detector.compute_fastflux_score(
            domain=domain,
            ttl=get_ttl(domain),           # from DNS query
            unique_ip_count=count_ips(domain),  # from DNS query
            query_rate=get_query_rate(domain)   # from logs
        )
        
        if ff_result['is_fastflux']:
            classification = 'Fast-Flux'
        else:
            classification = 'Benign/DGA/Suspicious'  # from your model
"""
