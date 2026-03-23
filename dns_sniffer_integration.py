"""
Real-Time DNS Sniffer Integration
Monitors DNS traffic, classifies domains in real-time, stores results
"""

import threading
import queue
import json
import logging
from datetime import datetime
from collections import defaultdict
from db_service import ThreatDatabase

# Scapy imports - will be installed by pip
try:
    from scapy.all import sniff, IP, DNS, DNSQR, Ether
except ImportError:
    print("Scapy not installed. Install with: pip install scapy")
    print("For Windows, may also need: pip install pyaudio")

from config import setup_logger

# Setup logging
logger = setup_logger("dns_sniffer", "logs/dns_sniffer.log")


class DNSPacketMetrics:
    """Tracks DNS query metrics for threat scoring"""

    def __init__(self, window_size=1000):
        self.window_size = window_size
        self.domain_queries = defaultdict(int)
        self.domain_ips = defaultdict(set)
        self.domain_first_seen = {}
        self.lock = threading.Lock()

    def record_query(self, domain, response_ip=None):
        """Record a DNS query/response"""
        with self.lock:
            self.domain_queries[domain] += 1
            if response_ip:
                self.domain_ips[domain].add(response_ip)
            if domain not in self.domain_first_seen:
                self.domain_first_seen[domain] = datetime.now()

    def get_metrics(self, domain):
        """Get metrics for a domain"""
        with self.lock:
            return {
                "query_rate": self.domain_queries.get(domain, 0),
                "unique_ip_count": len(self.domain_ips.get(domain, set())),
                "first_seen": self.domain_first_seen.get(domain),
            }

    def clear_old_entries(self, keep_domains=100):
        """Keep memory footprint bounded"""
        with self.lock:
            if len(self.domain_queries) > keep_domains:
                # Keep only the most queried domains
                most_common = sorted(
                    self.domain_queries.items(), key=lambda x: x[1], reverse=True
                )[:keep_domains]
                domains_to_keep = {d[0] for d in most_common}

                self.domain_queries = {
                    d: self.domain_queries[d]
                    for d in domains_to_keep
                    if d in self.domain_queries
                }
                self.domain_ips = {
                    d: self.domain_ips[d]
                    for d in domains_to_keep
                    if d in self.domain_ips
                }
                self.domain_first_seen = {
                    d: self.domain_first_seen[d]
                    for d in domains_to_keep
                    if d in self.domain_first_seen
                }


class DNSSnifferIntegration:
    """
    Real-time DNS traffic sniffer with threat detection
    Captures DNS queries, extracts domains, classifies them in background threads
    """

    def __init__(
        self,
        interface=None,
        queue_size=5000,
        num_workers=3,
        classifier=None,
        db=None,
    ):
        """
        Initialize DNS sniffer

        Args:
            interface: Network interface to sniff on (auto-detect if None)
            queue_size: Size of threat classification queue
            num_workers: Number of background classification threads
            classifier: IntegratedThreatClassifier instance
            db: ThreatDatabase instance
        """
        self.interface = interface
        self.num_workers = num_workers
        self.threat_queue = queue.Queue(maxsize=queue_size)
        self.running = False
        self.db = db or ThreatDatabase()
        self.classifier = classifier
        self.metrics = DNSPacketMetrics()
        self.stats = {
            "packets_received": 0,
            "dns_queries": 0,
            "domains_classified": 0,
            "threats_detected": 0,
            "queue_errors": 0,
        }
        self.lock = threading.Lock()

        logger.info(f"DNSSnifferIntegration initialized on interface={interface}")

    def packet_callback(self, packet):
        """
        Called for each captured packet
        Extracts DNS queries and queues them for classification

        Args:
            packet: Scapy packet object
        """
        try:
            with self.lock:
                self.stats["packets_received"] += 1

            # Check if DNS layer present and is a query (qr=0)
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                # Extract questions (domains being queried)
                if packet[DNS].qd:
                    for question in packet[DNS].qd:
                        domain = question.qname.decode("utf-8").rstrip(".")

                        # Get source IP if available
                        src_ip = None
                        if packet.haslayer(IP):
                            src_ip = packet[IP].src

                        # Record metrics
                        self.metrics.record_query(domain, src_ip)

                        with self.lock:
                            self.stats["dns_queries"] += 1

                        # Queue for classification
                        try:
                            self.threat_queue.put(
                                {
                                    "domain": domain,
                                    "timestamp": datetime.now(),
                                    "src_ip": src_ip,
                                    "packet_id": packet.ID if hasattr(packet, "ID") else None,
                                },
                                block=False,
                            )
                        except queue.Full:
                            with self.lock:
                                self.stats["queue_errors"] += 1
                            logger.warning("Threat queue full, dropping packet")

        except Exception as e:
            logger.error(f"Packet processing error: {e}", exc_info=True)

    def classification_worker(self, worker_id):
        """
        Background worker thread: classify domains from queue
        Each worker processes domains independently

        Args:
            worker_id: Worker thread identifier
        """
        logger.info(f"Classification worker {worker_id} started")

        while self.running:
            try:
                # Get item from queue with timeout
                item = self.threat_queue.get(timeout=1)
                domain = item["domain"]

                if not self.classifier:
                    logger.warning(
                        "Classifier not configured, queue item dropped for domain: "
                        + domain
                    )
                    self.threat_queue.task_done()
                    continue

                try:
                    # Get metrics for this domain
                    domain_metrics = self.metrics.get_metrics(domain)

                    # Classify domain
                    result = self.classifier.classify(
                        domain=domain,
                        ttl=3600,  # Default
                        unique_ip_count=domain_metrics.get("unique_ip_count", 1),
                        query_rate=min(domain_metrics.get("query_rate", 1), 10000),
                    )

                    with self.lock:
                        self.stats["domains_classified"] += 1

                    # Store result in database
                    detection_id = self.db.insert_threat_detection(
                        {
                            "domain": domain,
                            "final_class": result.get("final_class"),
                            "confidence": result.get("base_confidence", 0),
                            "ff_score": result.get("fastflux_analysis", {}).get(
                                "fastflux_score", 0
                            ),
                            "is_fastflux": result.get("fastflux_analysis", {}).get(
                                "is_fastflux", False
                            ),
                            "source_ip": item.get("src_ip"),
                            "model_version": "v1.0",
                        }
                    )

                    # Alert if malicious
                    final_class = result.get("final_class")
                    if final_class in [1, 2, 3]:  # Suspicious, DGA, or Fast-Flux
                        prediction = result.get("final_prediction", "Unknown")
                        ff_score = result.get("fastflux_analysis", {}).get(
                            "fastflux_score", 0
                        )
                        logger.warning(
                            f"[THREAT] domain={domain} | class={prediction} | ff_score={ff_score:.2f} | id={detection_id}"
                        )

                        with self.lock:
                            self.stats["threats_detected"] += 1

                        # Could add webhook/email alert here
                        # self.alert_threat(domain, result)

                except Exception as e:
                    logger.error(
                        f"Classification error for domain {domain}: {e}", exc_info=True
                    )

                finally:
                    self.threat_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}", exc_info=True)

    def start(self, capture_filter="port 53 or port 5353"):
        """
        Start DNS traffic sniffing

        Args:
            capture_filter: tcpdump-style filter (default: DNS port 53 and mDNS 5353)
        """
        try:
            self.running = True

            # Start worker threads
            workers = []
            for i in range(self.num_workers):
                worker = threading.Thread(
                    target=self.classification_worker, args=(i,), daemon=True
                )
                worker.start()
                workers.append(worker)
                logger.info(f"Started classification worker {i}")

            # Start packet sniffer
            logger.info(
                f"Starting DNS packet capture on interface={self.interface} with filter={capture_filter}"
            )

            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                filter=capture_filter,
                store=False,
                # stop_filter=lambda x: not self.running,
            )

        except PermissionError:
            logger.error(
                "Permission denied - DNS sniffing requires administrator/root privileges"
            )
            raise
        except Exception as e:
            logger.error(f"Sniffer error: {e}", exc_info=True)
            raise
        finally:
            self.stop()

    def stop(self):
        """Stop sniffing and cleanup"""
        logger.info("Stopping DNS sniffer...")
        self.running = False

        # Wait for queue to be processed
        logger.info(f"Waiting for {self.threat_queue.qsize()} items in queue...")
        self.threat_queue.join()

        logger.info("Sniffer stopped")

    def get_stats(self):
        """Get current sniffer statistics"""
        with self.lock:
            return {
                **self.stats,
                "queue_size": self.threat_queue.qsize(),
                "timestamp": datetime.now().isoformat(),
            }

    def print_stats(self):
        """Print formatted statistics"""
        stats = self.get_stats()
        print("\n" + "=" * 60)
        print("DNS SNIFFER STATISTICS")
        print("=" * 60)
        print(f"Packets Received:      {stats['packets_received']:,}")
        print(f"DNS Queries:           {stats['dns_queries']:,}")
        print(f"Domains Classified:    {stats['domains_classified']:,}")
        print(f"Threats Detected:      {stats['threats_detected']:,}")
        print(f"Queue Size:            {stats['queue_size']}")
        print(f"Queue Errors:          {stats['queue_errors']}")
        if stats['dns_queries'] > 0:
            print(f"Threat Rate:           {stats['threats_detected']/stats['dns_queries']*100:.2f}%")
        print(f"Timestamp:             {stats['timestamp']}")
        print("=" * 60 + "\n")


# Standalone mode testing
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    # List available interfaces
    try:
        from scapy.all import get_if_list

        print("Available network interfaces:")
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        print()
    except Exception as e:
        print(f"Could not list interfaces: {e}")
        print("Proceeding with default interface...")

    # Initialize database
    db = ThreatDatabase()
    print(f"[OK] Database initialized: {db.db_path}\n")

    # Note: For testing without classifier, create dummy sniffer
    print("Note: To run sniffer with actual threat classification:")
    print("  from fastflux_integration import IntegratedThreatClassifier")
    print("  classifier = IntegratedThreatClassifier()")
    print("  sniffer = DNSSnifferIntegration(interface='eth0', classifier=classifier)")
    print("\nFor Windows, use 'Ethernet', 'Wi-Fi', etc.")
    print("Run with administrator privileges!")
    print("\nExample usage (on Linux):")
    print("  sudo python dns_sniffer_integration.py  # Will fail without classifier, but tests packet capture")
