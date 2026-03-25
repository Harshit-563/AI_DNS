"""
Input validators for DNS threat detection API
Sanitize and validate all inputs before processing
"""

import re
from typing import Tuple


class DomainValidator:
    """Validate DNS threat detection inputs"""
    
    @staticmethod
    def validate_domain(domain: str) -> Tuple[bool, str]:
        """
        Validate domain format
        Returns: (is_valid, error_message)
        """
        if not isinstance(domain, str):
            return False, "Domain must be string"
        
        if len(domain) == 0:
            return False, "Domain cannot be empty"
        
        if len(domain) > 253:
            return False, f"Domain too long: {len(domain)} > 253"
        
        # Check valid characters (a-z, 0-9, dot, hyphen)
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return False, "Domain contains invalid characters"
        
        # Check format
        if domain.startswith('.') or domain.endswith('.'):
            return False, "Domain cannot start/end with dot"
        
        if '..' in domain:
            return False, "Domain contains consecutive dots"
        
        # Check TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return False, "Domain must have at least one dot"
        
        tld = parts[-1]
        if len(tld) < 2:
            return False, "TLD too short"
        
        if not tld.isalpha():
            return False, "TLD must contain only letters"
        
        # Check for valid label length (63 chars max per label)
        for part in parts:
            if len(part) > 63:
                return False, f"Domain label too long: {len(part)} > 63"
            if len(part) == 0:
                return False, "Domain has empty label"
        
        return True, ""
    
    @staticmethod
    def validate_network_metrics(ttl, unique_ip_count, query_rate) -> Tuple[bool, str]:
        """Validate network metrics"""
        
        # TTL validation
        if not isinstance(ttl, (int, float)):
            return False, "TTL must be numeric"
        if ttl < 0:
            return False, "TTL cannot be negative"
        if ttl > 2147483647:  # Max 32-bit int
            return False, "TTL out of range"
        
        # IP count validation
        if not isinstance(unique_ip_count, (int, float)):
            return False, "unique_ip_count must be numeric"
        if unique_ip_count < 0:
            return False, "unique_ip_count cannot be negative"
        if unique_ip_count > 10000:
            return False, "unique_ip_count unreasonably high (>10000)"
        
        # Query rate validation
        if not isinstance(query_rate, (int, float)):
            return False, "query_rate must be numeric"
        if query_rate < 0:
            return False, "query_rate cannot be negative"
        
        return True, ""
    
    @staticmethod
    def sanitize_domain(domain: str) -> str:
        """Clean up domain for processing"""
        return domain.lower().strip()
    
    @staticmethod
    def sanitize_numeric(value) -> float:
        """Convert to float safely"""
        try:
            return float(value) if value is not None else 0.0
        except (ValueError, TypeError):
            return 0.0


class RequestValidator:
    """Validate incoming API requests"""
    
    @staticmethod
    def validate_classify_request(data: dict) -> Tuple[bool, str, dict]:
        """
        Validate classify request
        Returns: (is_valid, error_message, sanitized_data)
        """
        
        if not data or not isinstance(data, dict):
            return False, "Request body must be JSON object", {}
        
        # Check required fields
        if 'domain' not in data:
            return False, "Missing required field: domain", {}
        
        domain = data['domain']
        is_valid, error = DomainValidator.validate_domain(domain)
        if not is_valid:
            return False, f"Invalid domain: {error}", {}
        
        # Sanitize domain
        domain = DomainValidator.sanitize_domain(domain)
        
        # Get optional fields with defaults
        ttl = data.get('ttl', 3600)
        unique_ip_count = data.get('unique_ip_count', 1)
        query_rate = data.get('query_rate', 100)
        
        # Validate network metrics
        is_valid, error = DomainValidator.validate_network_metrics(
            ttl, unique_ip_count, query_rate
        )
        if not is_valid:
            return False, f"Invalid network metrics: {error}", {}
        
        # Sanitize numeric values
        ttl = DomainValidator.sanitize_numeric(ttl)
        unique_ip_count = int(max(0, DomainValidator.sanitize_numeric(unique_ip_count)))
        query_rate = DomainValidator.sanitize_numeric(query_rate)
        
        # Return sanitized data
        sanitized = {
            'domain': domain,
            'ttl': ttl,
            'unique_ip_count': unique_ip_count,
            'query_rate': query_rate
        }
        
        return True, "", sanitized
    
    @staticmethod
    def validate_feedback_request(data: dict) -> Tuple[bool, str, dict]:
        """Validate feedback submission"""
        
        if not data or not isinstance(data, dict):
            return False, "Request body must be JSON object", {}
        
        if 'domain' not in data or 'feedback' not in data:
            return False, "Missing required fields: domain, feedback", {}
        
        domain = data['domain']
        feedback = data['feedback']
        
        # Validate domain
        is_valid, error = DomainValidator.validate_domain(domain)
        if not is_valid:
            return False, f"Invalid domain: {error}", {}
        
        # Validate feedback (0=correct, 1=false_positive, 2=false_negative)
        if not isinstance(feedback, int) or feedback not in [0, 1, 2]:
            return False, "Feedback must be 0 (correct), 1 (false positive), or 2 (false negative)", {}
        
        domain = DomainValidator.sanitize_domain(domain)
        
        return True, "", {'domain': domain, 'feedback': feedback}


# Test validators
if __name__ == "__main__":
    print("Testing Validators\n")
    
    # Test valid domain
    print("Test 1: Valid domain")
    is_valid, error = DomainValidator.validate_domain("google.com")
    print(f"  google.com: {is_valid} - {error}\n")
    
    # Test invalid domain
    print("Test 2: Invalid domains")
    invalid_domains = ["", ".com", "example.", "exam ple.com", "a" * 300]
    for domain in invalid_domains:
        is_valid, error = DomainValidator.validate_domain(domain)
        print(f"  '{domain}': {is_valid} - {error}")
    print()
    
    # Test network metrics
    print("Test 3: Valid metrics")
    is_valid, error = DomainValidator.validate_network_metrics(3600, 5, 1000)
    print(f"  Valid metrics: {is_valid} - {error}\n")
    
    print("Test 4: Invalid metrics")
    invalid_metrics = [(-1, 5, 1000), (3600, -1, 1000), (3600, 5, -100)]
    for ttl, ips, rate in invalid_metrics:
        is_valid, error = DomainValidator.validate_network_metrics(ttl, ips, rate)
        print(f"  ttl={ttl}, ips={ips}, rate={rate}: {is_valid} - {error}")
    print()
    
    # Test request validation
    print("Test 5: Valid request")
    req = {'domain': 'example.com', 'ttl': 3600, 'unique_ip_count': 1, 'query_rate': 100}
    is_valid, error, data = RequestValidator.validate_classify_request(req)
    print(f"  Valid request: {is_valid} - {error}\n")
    
    # Test missing field
    print("Test 6: Invalid request (missing domain)")
    req = {'ttl': 3600}
    is_valid, error, data = RequestValidator.validate_classify_request(req)
    print(f"  Missing domain: {is_valid} - {error}\n")
    
    print("✅ All tests passed!")
