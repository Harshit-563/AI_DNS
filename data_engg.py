import math
from collections import Counter, defaultdict
import nltk
from nltk.corpus import words as english_words

class DomainFeatureExtractor:
    """Extract lexical, statistical, and structural features from domains"""
    
    def __init__(self):
        self.common_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'co', 'uk', 'ca', 'de', 'fr',
            'au', 'us', 'ru', 'cn', 'in', 'br', 'jp', 'es', 'it', 'mx',
            'nl', 'be', 'ch', 'se', 'no', 'dk', 'fi', 'pl', 'cz', 'gr'
        }
        
    # ==================== LEXICAL FEATURES ====================
    
    def domain_length(self, domain):
        """Length of domain name"""
        return len(domain)
    
    def subdomain_count(self, domain):
        """Number of subdomains"""
        return domain.count('.') + 1
    
    def character_entropy(self, domain):
        """Shannon entropy of domain name (higher = more random)"""
        domain_clean = domain.replace('.', '')
        if len(domain_clean) == 0:
            return 0
        
        freq = Counter(domain_clean)
        entropy = 0
        for count in freq.values():
            p = count / len(domain_clean)
            entropy -= p * math.log2(p)
        return entropy
    
    def digit_ratio(self, domain):
        """Ratio of digits to total characters"""
        domain_clean = domain.replace('.', '')
        if len(domain_clean) == 0:
            return 0
        digits = sum(1 for c in domain_clean if c.isdigit())
        return digits / len(domain_clean)
    
    def vowel_ratio(self, domain):
        """Ratio of vowels to total characters"""
        domain_clean = domain.replace('.', '').lower()
        if len(domain_clean) == 0:
            return 0
        vowels = sum(1 for c in domain_clean if c in 'aeiou')
        return vowels / len(domain_clean)
    
    def consonant_ratio(self, domain):
        """Ratio of consonants to total characters"""
        domain_clean = domain.replace('.', '').lower()
        if len(domain_clean) == 0:
            return 0
        consonants = sum(1 for c in domain_clean if c.isalpha() and c not in 'aeiou')
        return consonants / len(domain_clean)
    
    def special_char_count(self, domain):
        """Count of special characters (hyphens, underscores, etc.)"""
        return sum(1 for c in domain if c in '-_')
    
    def hyphen_ratio(self, domain):
        """Ratio of hyphens"""
        domain_clean = domain.replace('.', '')
        if len(domain_clean) == 0:
            return 0
        return domain.count('-') / len(domain_clean)
    
    def consecutive_consonants(self, domain):
        """Maximum consecutive consonants"""
        domain_clean = domain.replace('.', '').lower()
        max_consecutive = 0
        current = 0
        for c in domain_clean:
            if c.isalpha() and c not in 'aeiou':
                current += 1
                max_consecutive = max(max_consecutive, current)
            else:
                current = 0
        return max_consecutive
    
    def consecutive_digits(self, domain):
        """Maximum consecutive digits"""
        max_consecutive = 0
        current = 0
        for c in domain:
            if c.isdigit():
                current += 1
                max_consecutive = max(max_consecutive, current)
            else:
                current = 0
        return max_consecutive
    
    # ==================== N-GRAM FEATURES ====================
    
    def bigram_entropy(self, domain):
        """Entropy of bigrams"""
        domain_clean = domain.replace('.', '')
        if len(domain_clean) < 2:
            return 0
        
        bigrams = [domain_clean[i:i+2] for i in range(len(domain_clean)-1)]
        freq = Counter(bigrams)
        entropy = 0
        for count in freq.values():
            p = count / len(bigrams)
            entropy -= p * math.log2(p)
        return entropy
    
    def trigram_entropy(self, domain):
        """Entropy of trigrams"""
        domain_clean = domain.replace('.', '')
        if len(domain_clean) < 3:
            return 0
        
        trigrams = [domain_clean[i:i+3] for i in range(len(domain_clean)-2)]
        freq = Counter(trigrams)
        entropy = 0
        for count in freq.values():
            p = count / len(trigrams)
            entropy -= p * math.log2(p)
        return entropy
    
    def unique_bigram_ratio(self, domain):
        """Ratio of unique bigrams to total bigrams"""
        domain_clean = domain.replace('.', '')
        if len(domain_clean) < 2:
            return 0
        
        bigrams = [domain_clean[i:i+2] for i in range(len(domain_clean)-1)]
        return len(set(bigrams)) / len(bigrams)
    
    # ==================== STRUCTURAL FEATURES ====================
    
    def tld_length(self, domain):
        """Length of TLD"""
        parts = domain.split('.')
        if len(parts) > 0:
            return len(parts[-1])
        return 0
    
    def sld_length(self, domain):
        """Length of second-level domain"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return len(parts[-2])
        elif len(parts) == 1:
            return len(parts[0])
        return 0
    
    def is_common_tld(self, domain):
        """Is TLD in common TLD list"""
        tld = domain.split('.')[-1].lower()
        return 1 if tld in self.common_tlds else 0
    
    def subdomain_depth(self, domain):
        """Depth of subdomains"""
        return max(0, domain.count('.'))
    
    # ==================== RANDOMNESS & DGA DETECTION ====================
    
    def dga_heuristic_score(self, domain):
        """
        DGA heuristic score based on multiple factors
        Returns score 0-1, higher = more likely DGA
        """
        score = 0
        
        # High entropy is DGA indicator
        entropy = self.character_entropy(domain)
        if entropy > 4.0:
            score += 0.3
        
        # High consonant ratio is DGA indicator
        consonant_ratio = self.consonant_ratio(domain)
        if consonant_ratio > 0.7:
            score += 0.2
        
        # Low vowel ratio is DGA indicator
        vowel_ratio = self.vowel_ratio(domain)
        if vowel_ratio < 0.25:
            score += 0.2
        
        # Many consecutive consonants
        consec_cons = self.consecutive_consonants(domain)
        if consec_cons > 5:
            score += 0.15
        
        # Uncommon TLD
        if not self.is_common_tld(domain):
            score += 0.15
        
        return min(score, 1.0)
    
    def randomness_score(self, domain):
        """
        Overall randomness score
        Returns 0-1, higher = more random (likely malicious)
        """
        domain_clean = domain.replace('.', '')
        
        # Character distribution uniformity (higher = more random)
        freq = Counter(domain_clean)
        max_freq = max(freq.values()) if freq else 1
        uniformity = 1.0 - (max_freq / len(domain_clean))
        
        # Combine with entropy
        entropy = self.character_entropy(domain)
        normalized_entropy = entropy / 5.0  # Max entropy ~5 for DNS
        
        return (uniformity + normalized_entropy) / 2.0
    
    # ==================== DICTIONARY & WORD FEATURES ====================
    
    def english_word_percentage(self, domain):
        """Percentage of domain that is English words"""
        try:
            from nltk.corpus import words
            word_list = set(words.words())
        except:
            # Fallback list of common words
            word_list = set([
                'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have',
                'i', 'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you',
                'do', 'at', 'this', 'but', 'his', 'by', 'from', 'microsoft',
                'google', 'apple', 'amazon', 'facebook', 'twitter', 'youtube'
            ])
        
        domain_clean = domain.replace('.', '').lower()
        
        # Try to find English words in domain
        found_words = 0
        for word in word_list:
            if word in domain_clean:
                found_words += 1
        
        return found_words / max(len(word_list), 1)
    
    def dictionary_word_score(self, domain):
        """
        Score based on dictionary words
        Legitimate domains often contain real words
        """
        parts = domain.split('.')
        score = 0
        
        common_prefixes = {
            'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'sftp', 'ssh',
            'api', 'cdn', 'static', 'img', 'images', 'media', 'assets'
        }
        
        for part in parts:
            if part.lower() in common_prefixes:
                score += 1
        
        return min(score / 5.0, 1.0)
    
    # ==================== NUMBER PATTERN FEATURES ====================
    
    def digit_in_sld(self, domain):
        """Does SLD contain digits"""
        parts = domain.split('.')
        if len(parts) >= 2:
            sld = parts[-2]
            return 1 if any(c.isdigit() for c in sld) else 0
        return 0
    
    def numbers_at_end(self, domain):
        """Does domain end with numbers"""
        domain_clean = domain.replace('.', '')
        for i in range(len(domain_clean)-1, -1, -1):
            if not domain_clean[i].isdigit():
                return 0 if domain_clean[i] == '.' else i == len(domain_clean) - 1
        return 1
    
    # ==================== FAST FLUX SPECIFIC FEATURES ====================
    
    def subdomain_variability_indicator(self, domain):
        """
        Indicator for fast flux (many changing subdomains)
        Benign: few subdomains. Malicious FF: many random subdomains
        """
        parts = domain.split('.')
        if len(parts) <= 2:
            return 0
        
        # Check if subdomains look random
        subdomains = parts[:-2]
        random_score = sum(self.character_entropy(sub) / 5.0 for sub in subdomains) / len(subdomains)
        return random_score
    
    def tld_repetition(self, domain):
        """Count of repeated TLD-like patterns (FF indicator)"""
        return domain.count('.')
    
    # ==================== EXTRACT ALL FEATURES ====================
    
    def extract_all_features(self, domain):
        """Extract all features for a domain"""
        features = {
            # Lexical Features
            'domain_length': self.domain_length(domain),
            'subdomain_count': self.subdomain_count(domain),
            'character_entropy': self.character_entropy(domain),
            'digit_ratio': self.digit_ratio(domain),
            'vowel_ratio': self.vowel_ratio(domain),
            'consonant_ratio': self.consonant_ratio(domain),
            'special_char_count': self.special_char_count(domain),
            'hyphen_ratio': self.hyphen_ratio(domain),
            'consecutive_consonants': self.consecutive_consonants(domain),
            'consecutive_digits': self.consecutive_digits(domain),
            
            # N-gram Features
            'bigram_entropy': self.bigram_entropy(domain),
            'trigram_entropy': self.trigram_entropy(domain),
            'unique_bigram_ratio': self.unique_bigram_ratio(domain),
            
            # Structural Features
            'tld_length': self.tld_length(domain),
            'sld_length': self.sld_length(domain),
            'is_common_tld': self.is_common_tld(domain),
            'subdomain_depth': self.subdomain_depth(domain),
            
            # Advanced Features
            'dga_heuristic_score': self.dga_heuristic_score(domain),
            'randomness_score': self.randomness_score(domain),
            'english_word_percentage': self.english_word_percentage(domain),
            'dictionary_word_score': self.dictionary_word_score(domain),
            'digit_in_sld': self.digit_in_sld(domain),
            'numbers_at_end': self.numbers_at_end(domain),
            
            # Fast Flux Features
            'subdomain_variability': self.subdomain_variability_indicator(domain),
            'tld_repetition_count': self.tld_repetition(domain),
        }
        return features

# =====================================================
# FAST FLUX DETECTION MODULE
# =====================================================

class FastFluxDetector:
    """
    Detect Fast Flux networks using domain and network features.
    Fast Flux: Multiple IP addresses for same domain, frequently changing
    """
    
    def __init__(self):
        self.extractor = DomainFeatureExtractor()
    
    # ==================== FAST FLUX DOMAIN FEATURES ====================
    
    def domain_lexical_score(self, domain):
        """
        Score domain based on lexical characteristics.
        High entropy, low vowel ratio, uncommon words = higher FF probability
        """
        score = 0
        
        # High entropy (random-looking domains)
        entropy = self.extractor.character_entropy(domain)
        if entropy > 4.0:
            score += 0.25
        
        # Low vowel ratio (random strings)
        vowel_ratio = self.extractor.vowel_ratio(domain)
        if vowel_ratio < 0.25:
            score += 0.25
        
        # Many consecutive consonants
        if self.extractor.consecutive_consonants(domain) > 4:
            score += 0.15
        
        # Contains numbers in SLD
        if self.extractor.digit_in_sld(domain):
            score += 0.15
        
        # Uncommon TLD
        if not self.extractor.is_common_tld(domain):
            score += 0.20
        
        return min(score, 1.0)
    
    def subdomain_complexity_score(self, domain):
        """
        FF networks often use many random subdomains for load distribution.
        Returns score 0-1 where higher = more likely FF.
        """
        parts = domain.split('.')
        if len(parts) <= 2:
            return 0
        
        subdomains = parts[:-2]
        score = 0
        
        # Many subdomains (FF uses many for distribution)
        if len(subdomains) >= 3:
            score += 0.3
        elif len(subdomains) == 2:
            score += 0.15
        
        # Random subdomains
        random_subdomains = 0
        for sub in subdomains:
            if self.extractor.character_entropy(sub) > 3.5:
                random_subdomains += 1
        
        if len(subdomains) > 0:
            score += (random_subdomains / len(subdomains)) * 0.5
        
        return min(score, 1.0)
    
    def domain_age_indicator(self, domain):
        """
        FF networks often use recently registered domains.
        This is a heuristic based on domain naming patterns.
        """
        score = 0
        
        # Randomly generated names (short time to operation)
        if self.extractor.randomness_score(domain) > 0.6:
            score += 0.3
        
        # No recognizable brand/word
        if self.extractor.english_word_percentage(domain) < 0.1:
            score += 0.3
        
        # Uncommon TLD often means newer/suspicious
        if not self.extractor.is_common_tld(domain):
            score += 0.2
        
        return min(score, 1.0)
    
    # ==================== NETWORK-BASED FEATURES ====================
    
    def ttl_vulnerability_score(self, ttl_value):
        """
        Very low TTL (< 300 seconds / 5 min) indicates IP changes.
        FF networks need low TTL to switch IPs frequently.
        
        Args:
            ttl_value: TTL in seconds
        """
        if ttl_value is None or ttl_value <= 0:
            return 0.5  # Unknown = medium risk
        
        ttl_value = int(ttl_value)
        
        if ttl_value < 60:
            return 1.0  # Very suspicious
        elif ttl_value < 300:
            return 0.8  # Suspicious
        elif ttl_value < 900:
            return 0.4  # Somewhat suspicious
        elif ttl_value < 3600:
            return 0.2  # Low risk
        else:
            return 0.0  # Normal/safe
    
    def ip_diversity_score(self, unique_ip_count):
        """
        FF networks have many IPs for load distribution and fast switching.
        
        Args:
            unique_ip_count: Number of unique IPs serving the domain
        """
        if unique_ip_count is None:
            return 0.5
        
        unique_ip_count = int(unique_ip_count)
        
        if unique_ip_count >= 10:
            return 1.0   # Very FF-like
        elif unique_ip_count >= 5:
            return 0.8   # Likely FF
        elif unique_ip_count >= 3:
            return 0.6   # Possibly FF
        elif unique_ip_count >= 2:
            return 0.4   # Multiple IPs (suspicious)
        else:
            return 0.1   # Single IP (normal)
    
    def query_rate_anomaly(self, query_rate):
        """
        Unusually high query rate can indicate botnet C&C or FF hosting.
        Very low query rate for unknown domain = suspicious.
        
        Args:
            query_rate: Queries per some time unit (e.g., daily average)
        """
        if query_rate is None:
            return 0.5
        
        query_rate = float(query_rate)
        
        # Extremely high query rate = possible C&C/hosting
        if query_rate > 10000:
            return 0.9
        elif query_rate > 1000:
            return 0.6
        elif query_rate > 100:
            return 0.3
        elif query_rate > 10:
            return 0.2
        elif query_rate > 0:
            return 0.1
        else:
            return 0.0
    
    # ==================== COMBINED FAST FLUX SCORE ====================
    
    def compute_fastflux_score(self, domain, ttl=None, unique_ip_count=None, query_rate=None):
        """
        Comprehensive Fast Flux score combining domain and network features.
        
        Args:
            domain: Domain name (string)
            ttl: TTL value in seconds (int or None)
            unique_ip_count: Number of unique IPs (int or None)
            query_rate: Query rate metric (float or None)
        
        Returns:
            Dictionary with score and component breakdown
        """
        # Domain-based scores (weighted 40%)
        lexical_score = self.domain_lexical_score(domain)          # 15%
        subdomain_score = self.subdomain_complexity_score(domain)  # 15%
        age_score = self.domain_age_indicator(domain)              # 10%
        
        # Network-based scores (weighted 60%)
        ttl_score = self.ttl_vulnerability_score(ttl)              # 25%
        ip_score = self.ip_diversity_score(unique_ip_count)        # 25%
        query_score = self.query_rate_anomaly(query_rate)          # 10%
        
        # Weighted combination
        domain_component = (lexical_score * 0.15 + 
                          subdomain_score * 0.15 + 
                          age_score * 0.10)
        
        network_component = (ttl_score * 0.25 + 
                           ip_score * 0.25 + 
                           query_score * 0.10)
        
        final_score = domain_component + network_component
        
        return {
            'fastflux_score': final_score,
            'domain_lexical_score': lexical_score,
            'subdomain_complexity_score': subdomain_score,
            'domain_age_score': age_score,
            'ttl_score': ttl_score,
            'ip_diversity_score': ip_score,
            'query_rate_score': query_score,
            'is_fastflux': final_score > 0.6  # Threshold for FF classification
        }


extractor = DomainFeatureExtractor()
ff_detector = FastFluxDetector()

if __name__ == "__main__":
    test_domains = [
        'google.com',
        'xyw.xyz',
        'mail.amazon.com',
        'asdflkjhqwerty.xyz'
    ]

    print("\n" + "=" * 60)
    print("FEATURE EXTRACTION TEST")
    print("=" * 60)

    for domain in test_domains:
        features = extractor.extract_all_features(domain)
        print(f"\n{domain}:")
        for feat_name, feat_value in features.items():
            print(f"  {feat_name}: {feat_value:.4f}")
    
    print("\n\n" + "=" * 60)
    print("FAST FLUX DETECTION TEST")
    print("=" * 60)
    
    test_cases = [
        ('google.com', 3600, 1, 5000),           # Benign: high TTL, 1 IP, high query
        ('evil-flux-net.xyz', 60, 8, 500),       # FF: low TTL, many IPs
        ('suspicious.ru', 300, 3, 100),          # Suspicious: low TTL, multiple IPs
    ]
    
    for domain, ttl, ips, qrate in test_cases:
        result = ff_detector.compute_fastflux_score(domain, ttl, ips, qrate)
        print(f"\n{domain}:")
        print(f"  FF Score: {result['fastflux_score']:.3f}")
        print(f"  Is Fast Flux: {result['is_fastflux']}")
        print(f"  Details:")
        print(f"    - Domain Lexical: {result['domain_lexical_score']:.3f}")
        print(f"    - Subdomain Complexity: {result['subdomain_complexity_score']:.3f}")
        print(f"    - Domain Age: {result['domain_age_score']:.3f}")
        print(f"    - TTL Vulnerability: {result['ttl_score']:.3f}")
        print(f"    - IP Diversity: {result['ip_diversity_score']:.3f}")
        print(f"    - Query Rate: {result['query_rate_score']:.3f}")
