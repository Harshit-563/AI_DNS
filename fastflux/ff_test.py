import dns.resolver
import time
import random
import socket
from collections import defaultdict



class FastFluxTester:
    def __init__(self):
        self.data = defaultdict(lambda: {
            "ips": set(),
            "ttls": [],
            "timestamps": []
        })

    def resolve_domain(self, domain):
        try:
            resolver = dns.resolver.Resolver()
            # 👇 Automatically points to the server IP
            resolver.nameservers = ["127.0.0.1"] 

            answers = resolver.resolve(domain, 'A')
            
            ips = []
            ttl = answers.rrset.ttl if answers.rrset else 0

            for rdata in answers:
                ips.append(str(rdata))

            return ips, ttl
        except Exception as e:
            print(f"Error resolving: {e}")
            return [], 0

    def update(self, domain, ips, ttl):
        now = time.time()
        entry = self.data[domain]
        entry["ips"].update(ips)
        entry["timestamps"].append(now)
        if ttl > 0:
            entry["ttls"].append(ttl)

    def compute_score(self, domain):
        entry = self.data[domain]
        ip_count = len(entry["ips"])
        avg_ttl = sum(entry["ttls"]) / len(entry["ttls"]) if entry["ttls"] else 0
        query_rate = len(entry["timestamps"])

        score = 0
        if avg_ttl < 300: score += 0.4
        elif avg_ttl < 600: score += 0.2

        if ip_count >= 10: score += 0.4
        elif ip_count >= 5: score += 0.3
        elif ip_count >= 3: score += 0.2

        if query_rate > 20: score += 0.2
        elif query_rate > 10: score += 0.1

        return {
            "score": round(score, 3),
            "is_fastflux": score >= 0.6,
            "ip_count": ip_count,
            "avg_ttl": round(avg_ttl, 2),
            "queries": query_rate
        }

def run_flux_test(domain, iterations=20, delay=1):
    tester = FastFluxTester()
    print(f"\n[🔥] Testing domain: {domain}\n")

    for i in range(iterations):
        ips, ttl = tester.resolve_domain(domain)
        print(f"[{i+1}] IPs: {ips} | TTL: {ttl}")
        tester.update(domain, ips, ttl)
        time.sleep(delay)

    result = tester.compute_score(domain)
    print("\n=== RESULT ===")
    print(result)

    if result["is_fastflux"]:
        print("⚠️ FAST FLUX DETECTED")
    else:
        print("✅ NOT FAST FLUX (likely CDN or normal domain)")


if __name__ == "__main__":
    test_domains = [
        "google.com",               
        "simulated-botnet.xyz"      
    ]
    for d in test_domains:
        run_flux_test(d)