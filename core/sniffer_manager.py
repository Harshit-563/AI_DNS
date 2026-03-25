"""
Sniffer Manager
Manages lifecycle of DNS sniffer as a background service
Handles start, stop, and status operations
"""

import threading
import time
import logging
from typing import Optional
from core.dns_sniffer_integration import DNSSnifferIntegration
from core.fastflux_integration import IntegratedThreatClassifier
from core.db_service import ThreatDatabase

logger = logging.getLogger(__name__)


class SnifferManager:
    """
    Manages the DNS sniffer as a background service
    Handles starting, stopping, and checking status
    """

    def __init__(self):
        """Initialize sniffer manager"""
        self.sniffer: Optional[DNSSnifferIntegration] = None
        self.sniffer_thread: Optional[threading.Thread] = None
        self.running = False
        self.lock = threading.Lock()
        self.start_time = None
        self.error_message = None

        logger.info("SnifferManager initialized")

    def start(self, interface: str = None) -> bool:
        """
        Start the DNS sniffer as a background thread

        Args:
            interface: Network interface to sniff on
                      (auto-detect if None, or specify: 'eth0', 'Ethernet', 'Wi-Fi', etc.)

        Returns:
            bool: True if started successfully, False if already running or error
        """
        with self.lock:
            if self.running:
                logger.warning("Sniffer already running")
                return False

            try:
                # Initialize components
                logger.info(f"Starting DNS sniffer on interface: {interface}")
                classifier = IntegratedThreatClassifier(model_path="models/dns_rf_model.pkl")
                db = ThreatDatabase()

                # Create sniffer
                self.sniffer = DNSSnifferIntegration(
                    interface=interface,
                    classifier=classifier,
                    db=db,
                    num_workers=3,
                    queue_size=5000,
                )

                # Start sniffer in background thread
                self.sniffer_thread = threading.Thread(
                    target=self._run_sniffer,
                    daemon=True,
                    name="DNSSniffer"
                )
                self.sniffer_thread.start()
                self.running = True
                self.start_time = time.time()
                self.error_message = None

                logger.info("DNS sniffer started successfully")
                return True

            except PermissionError as e:
                self.error_message = "Admin/root privileges required for packet capture"
                logger.error(f"Permission error: {e}")
                return False
            except Exception as e:
                self.error_message = f"Failed to start sniffer: {str(e)}"
                logger.error(f"Sniffer start error: {e}", exc_info=True)
                return False

    def _run_sniffer(self):
        """Background thread: Run sniffer"""
        try:
            logger.info("Sniffer thread started")
            self.sniffer.start()
        except KeyboardInterrupt:
            logger.info("Sniffer interrupted")
        except Exception as e:
            self.error_message = f"Sniffer runtime error: {str(e)}"
            logger.error(f"Sniffer runtime error: {e}", exc_info=True)
        finally:
            self.running = False
            logger.info("Sniffer thread stopped")

    def stop(self) -> bool:
        """
        Stop the DNS sniffer

        Returns:
            bool: True if stopped successfully, False if not running
        """
        with self.lock:
            if not self.running or not self.sniffer:
                logger.warning("Sniffer not running")
                return False

            try:
                logger.info("Stopping DNS sniffer...")
                self.sniffer.stop()
                self.running = False

                logger.info("DNS sniffer stopped")
                return True

            except Exception as e:
                logger.error(f"Error stopping sniffer: {e}", exc_info=True)
                return False

    def is_running(self) -> bool:
        """Check if sniffer is running"""
        with self.lock:
            return self.running

    def get_status(self) -> dict:
        """
        Get current sniffer status

        Returns:
            dict: Status information
        """
        with self.lock:
            status = {
                "running": self.running,
                "start_time": self.start_time,
                "uptime_seconds": time.time() - self.start_time if self.start_time else 0,
                "error": self.error_message,
            }

            # Add sniffer statistics if running
            if self.running and self.sniffer:
                try:
                    stats = self.sniffer.get_stats()
                    status.update(stats)
                except Exception as e:
                    logger.error(f"Error getting sniffer stats: {e}")

            return status

    def get_stats(self) -> Optional[dict]:
        """
        Get sniffer statistics

        Returns:
            dict: Statistics if running, None otherwise
        """
        if not self.running or not self.sniffer:
            return None

        try:
            return self.sniffer.get_stats()
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return None

    def print_status(self):
        """Print formatted status"""
        status = self.get_status()
        print("\n" + "=" * 60)
        print("DNS SNIFFER STATUS")
        print("=" * 60)
        print(f"Running:           {status['running']}")

        if status["running"]:
            uptime_hours = status["uptime_seconds"] / 3600
            uptime_minutes = (status["uptime_seconds"] % 3600) / 60
            print(f"Uptime:            {int(uptime_hours)}h {int(uptime_minutes)}m")

            if "packets_received" in status:
                print(f"Packets Received:  {status['packets_received']:,}")
            if "dns_queries" in status:
                print(f"DNS Queries:       {status['dns_queries']:,}")
            if "domains_classified" in status:
                print(f"Domains Classified: {status['domains_classified']:,}")
            if "threats_detected" in status:
                print(f"Threats Detected:  {status['threats_detected']:,}")
            if "threat_rate" in status:
                threat_pct = status.get("threats_detected", 0) / max(status.get("dns_queries", 1), 1) * 100
                print(f"Threat Rate:       {threat_pct:.2f}%")

        if status["error"]:
            print(f"Error:             {status['error']}")

        print("=" * 60 + "\n")


# Global instance
_manager: Optional[SnifferManager] = None


def get_sniffer_manager() -> SnifferManager:
    """Get or create global sniffer manager"""
    global _manager
    if _manager is None:
        _manager = SnifferManager()
    return _manager


# CLI usage
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    manager = get_sniffer_manager()

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        interface = sys.argv[2] if len(sys.argv) > 2 else None

        if command == "start":
            print(f"Starting sniffer on interface: {interface}")
            success = manager.start(interface=interface)
            if success:
                print("[OK] Sniffer started")
                # Keep running
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\nStopping...")
                    manager.stop()
            else:
                print("[FAIL] Failed to start sniffer")
                if manager.error_message:
                    print(f"Error: {manager.error_message}")

        elif command == "stop":
            success = manager.stop()
            if success:
                print("[OK] Sniffer stopped")
            else:
                print("[FAIL] Sniffer not running")

        elif command == "status":
            manager.print_status()

        else:
            print(f"Unknown command: {command}")
            print("Usage: python sniffer_manager.py [start|stop|status] [interface]")

    else:
        print("DNS Sniffer Manager")
        print("Usage: python sniffer_manager.py [start|stop|status] [interface]")
        print("\nExamples:")
        print("  python sniffer_manager.py start eth0       # Linux")
        print("  python sniffer_manager.py start Ethernet   # Windows")
        print("  python sniffer_manager.py status")
        print("  python sniffer_manager.py stop")
        print("\nNote: Requires administrator/root privileges")
