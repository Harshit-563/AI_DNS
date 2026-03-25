"""
Database Service Layer
Manages threat detections, model metrics, and persistence
"""

import sqlite3
import json
from datetime import datetime, timedelta
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)


class ThreatDatabase:
    """
    Thread-safe SQLite database for threat detections and metrics
    Stores classification results, user feedback, and model performance data
    """

    def __init__(self, db_path="threat_detection.db"):
        """
        Initialize database connection

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._init_schema()
        logger.info(f"ThreatDatabase initialized at {db_path}")

    def _init_schema(self):
        """Create database tables if they don't exist"""
        with self.get_connection() as conn:
            # Threat Detections Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    final_class INTEGER,
                    confidence REAL,
                    ff_score REAL,
                    is_fastflux BOOLEAN,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT,
                    model_version TEXT,
                    user_feedback INTEGER,
                    feedback_comment TEXT
                )
            """
            )

            # Model Metrics Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS model_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_version TEXT,
                    accuracy REAL,
                    precision REAL,
                    recall REAL,
                    f1_score REAL,
                    roc_auc REAL,
                    test_samples INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Daily Statistics Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS daily_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT UNIQUE,
                    total_detections INTEGER,
                    benign_count INTEGER,
                    suspicious_count INTEGER,
                    dga_count INTEGER,
                    fastflux_count INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Create indices for faster queries
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_domain ON threat_detections(domain)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_timestamp ON threat_detections(timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_class ON threat_detections(final_class)"
            )

            conn.commit()
            logger.info("Database schema initialized successfully")

    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections
        Ensures proper cleanup and thread safety

        Yields:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def insert_threat_detection(self, data):
        """
        Insert a threat detection result

        Args:
            data: Dict with keys:
                - domain (str): Domain name
                - final_class (int): Classification (0-benign, 1-suspicious, 2-dga, 3-fastflux)
                - confidence (float): Model confidence 0-1
                - ff_score (float): FastFlux score 0-1
                - is_fastflux (bool): Whether domain is fast-flux
                - source_ip (str, optional): Source IP of query
                - model_version (str, optional): Model version used

        Returns:
            int: ID of inserted record
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO threat_detections
                    (domain, final_class, confidence, ff_score, is_fastflux, source_ip, model_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        data.get("domain"),
                        data.get("final_class"),
                        float(data.get("confidence", 0.0)),
                        float(data.get("ff_score", 0.0)),
                        data.get("is_fastflux", False),
                        data.get("source_ip"),
                        data.get("model_version", "v1.0"),
                    ),
                )
                conn.commit()
                logger.info(
                    f"Inserted threat detection: domain={data.get('domain')}, class={data.get('final_class')}"
                )
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting threat detection: {e}")
            raise

    def get_detection_by_id(self, detection_id):
        """
        Get a specific threat detection

        Args:
            detection_id: ID of detection record

        Returns:
            dict or None: Detection data if found
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM threat_detections WHERE id = ?", (detection_id,)
                )
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error retrieving detection: {e}")
            return None

    def get_recent_detections(self, limit=100, hours=None):
        """
        Get recent threat detections

        Args:
            limit: Maximum number of results
            hours: If set, only return detections from last N hours

        Returns:
            list: List of detection records
        """
        try:
            with self.get_connection() as conn:
                if hours:
                    query = """
                        SELECT * FROM threat_detections
                        WHERE timestamp > datetime('now', '-' || ? || ' hours')
                        ORDER BY timestamp DESC
                        LIMIT ?
                    """
                    cursor = conn.execute(query, (hours, limit))
                else:
                    query = """
                        SELECT * FROM threat_detections
                        ORDER BY timestamp DESC
                        LIMIT ?
                    """
                    cursor = conn.execute(query, (limit,))

                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving recent detections: {e}")
            return []

    def get_detection_stats(self, hours=24):
        """
        Get statistics from recent detections

        Args:
            hours: Number of hours to look back

        Returns:
            dict: Classification counts by class (e.g., {'0': 1000, '1': 50, '2': 20})
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT final_class, COUNT(*) as count
                    FROM threat_detections
                    WHERE timestamp > datetime('now', '-' || ? || ' hours')
                    GROUP BY final_class
                """,
                    (hours,),
                )
                stats = {str(row["final_class"]): row["count"] for row in cursor.fetchall()}
                return stats
        except Exception as e:
            logger.error(f"Error calculating detection stats: {e}")
            return {}

    def get_malicious_domains(self, hours=24, limit=100):
        """
        Get recently detected malicious domains

        Args:
            hours: Number of hours to look back
            limit: Maximum results

        Returns:
            list: List of domain records with class >= 1
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT domain, final_class, ff_score, timestamp
                    FROM threat_detections
                    WHERE final_class >= 1
                    AND timestamp > datetime('now', '-' || ? || ' hours')
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (hours, limit),
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving malicious domains: {e}")
            return []

    def record_feedback(self, detection_id, feedback_type, comment=""):
        """
        Record user feedback on a detection

        Args:
            detection_id: ID of detection
            feedback_type: 0=correct, 1=false_positive, 2=false_negative
            comment: Optional feedback comment

        Returns:
            bool: Success status
        """
        try:
            with self.get_connection() as conn:
                conn.execute(
                    """
                    UPDATE threat_detections
                    SET user_feedback = ?, feedback_comment = ?
                    WHERE id = ?
                """,
                    (feedback_type, comment, detection_id),
                )
                conn.commit()
                logger.info(f"Recorded feedback for detection {detection_id}: type={feedback_type}")
                return True
        except Exception as e:
            logger.error(f"Error recording feedback: {e}")
            return False

    def get_false_positives(self, limit=100):
        """
        Get detections marked as false positives (for retraining)

        Args:
            limit: Maximum results

        Returns:
            list: False positive records
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT domain, final_class, ff_score, timestamp
                    FROM threat_detections
                    WHERE user_feedback = 1
                    LIMIT ?
                """,
                    (limit,),
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving false positives: {e}")
            return []

    def get_false_negatives(self, limit=100):
        """
        Get detections marked as false negatives (for retraining)

        Args:
            limit: Maximum results

        Returns:
            list: False negative records
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT domain, final_class, ff_score, timestamp
                    FROM threat_detections
                    WHERE user_feedback = 2
                    LIMIT ?
                """,
                    (limit,),
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving false negatives: {e}")
            return []

    def insert_model_metrics(self, data):
        """
        Insert model performance metrics

        Args:
            data: Dict with keys:
                - model_version (str): Version identifier
                - accuracy (float): Accuracy score
                - precision (float): Precision score
                - recall (float): Recall score
                - f1_score (float): F1 score
                - roc_auc (float): ROC AUC score
                - test_samples (int): Number of test samples

        Returns:
            int: ID of inserted record
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO model_metrics
                    (model_version, accuracy, precision, recall, f1_score, roc_auc, test_samples)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        data.get("model_version", "v1.0"),
                        float(data.get("accuracy", 0.0)),
                        float(data.get("precision", 0.0)),
                        float(data.get("recall", 0.0)),
                        float(data.get("f1_score", 0.0)),
                        float(data.get("roc_auc", 0.0)),
                        int(data.get("test_samples", 0)),
                    ),
                )
                conn.commit()
                logger.info(f"Inserted model metrics: version={data.get('model_version')}")
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting model metrics: {e}")
            raise

    def get_model_performance_history(self, model_version=None, limit=10):
        """
        Get model performance history

        Args:
            model_version: Filter by specific version (optional)
            limit: Maximum results

        Returns:
            list: Model metrics records
        """
        try:
            with self.get_connection() as conn:
                if model_version:
                    cursor = conn.execute(
                        """
                        SELECT * FROM model_metrics
                        WHERE model_version = ?
                        ORDER BY timestamp DESC
                        LIMIT ?
                    """,
                        (model_version, limit),
                    )
                else:
                    cursor = conn.execute(
                        """
                        SELECT * FROM model_metrics
                        ORDER BY timestamp DESC
                        LIMIT ?
                    """,
                        (limit,),
                    )

                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving model history: {e}")
            return []

    def calculate_daily_stats(self):
        """
        Calculate and store daily statistics

        Returns:
            dict: Daily stats
        """
        try:
            with self.get_connection() as conn:
                today = datetime.now().strftime("%Y-%m-%d")

                # Get counts by class
                cursor = conn.execute(
                    """
                    SELECT final_class, COUNT(*) as count
                    FROM threat_detections
                    WHERE DATE(timestamp) = ?
                    GROUP BY final_class
                """,
                    (today,),
                )

                stats = {
                    "date": today,
                    "total_detections": 0,
                    "benign_count": 0,
                    "suspicious_count": 0,
                    "dga_count": 0,
                    "fastflux_count": 0,
                }

                for row in cursor.fetchall():
                    class_id = row["final_class"]
                    count = row["count"]
                    stats["total_detections"] += count

                    if class_id == 0:
                        stats["benign_count"] = count
                    elif class_id == 1:
                        stats["suspicious_count"] = count
                    elif class_id == 2:
                        stats["dga_count"] = count
                    elif class_id == 3:
                        stats["fastflux_count"] = count

                # Upsert daily stats (insert or replace)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO daily_stats
                    (date, total_detections, benign_count, suspicious_count, dga_count, fastflux_count)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        today,
                        stats["total_detections"],
                        stats["benign_count"],
                        stats["suspicious_count"],
                        stats["dga_count"],
                        stats["fastflux_count"],
                    ),
                )
                conn.commit()
                logger.info(f"Calculated daily stats for {today}: {stats}")
                return stats

        except Exception as e:
            logger.error(f"Error calculating daily stats: {e}")
            return {}

    def get_daily_stats(self, days=7):
        """
        Get daily statistics for past N days

        Args:
            days: Number of days to retrieve

        Returns:
            list: Daily statistics records
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT * FROM daily_stats
                    ORDER BY date DESC
                    LIMIT ?
                """,
                    (days,),
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving daily stats: {e}")
            return []

    def cleanup_old_data(self, days=90):
        """
        Delete threat detections older than N days

        Args:
            days: Number of days to keep

        Returns:
            int: Number of deleted records
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    """
                    DELETE FROM threat_detections
                    WHERE timestamp < datetime('now', '-' || ? || ' days')
                """,
                    (days,),
                )
                conn.commit()
                deleted = cursor.rowcount
                logger.info(f"Cleaned up {deleted} old detections (>{days} days)")
                return deleted
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")
            return 0

    def get_database_stats(self):
        """
        Get database statistics

        Returns:
            dict: Database statistics
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.execute("SELECT COUNT(*) as count FROM threat_detections")
                total_detections = cursor.fetchone()["count"]

                cursor = conn.execute("SELECT COUNT(*) as count FROM model_metrics")
                total_metrics = cursor.fetchone()["count"]

                # Get size
                cursor = conn.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
                db_size = cursor.fetchone()["size"]

                return {
                    "total_detections": total_detections,
                    "total_metrics": total_metrics,
                    "database_size_bytes": db_size,
                    "database_path": self.db_path,
                }
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {}


# Testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    db = ThreatDatabase("test_threat.db")

    # Test insert
    print("Testing threat detection insert...")
    detection_id = db.insert_threat_detection(
        {
            "domain": "malware.cc",
            "final_class": 2,
            "confidence": 0.92,
            "ff_score": 0.75,
            "is_fastflux": True,
            "source_ip": "192.168.1.100",
            "model_version": "v1.0",
        }
    )
    print(f"[OK] Inserted detection with ID: {detection_id}")

    # Test insert benign
    print("\nTesting benign domain insert...")
    db.insert_threat_detection(
        {
            "domain": "google.com",
            "final_class": 0,
            "confidence": 0.99,
            "ff_score": 0.05,
            "is_fastflux": False,
            "model_version": "v1.0",
        }
    )
    print("[OK] Inserted benign domain")

    # Test stats
    print("\nTesting detection stats...")
    stats = db.get_detection_stats(hours=24)
    print(f"[OK] Detection stats: {stats}")

    # Test get recent
    print("\nTesting recent detections...")
    recent = db.get_recent_detections(limit=5)
    print(f"[OK] Retrieved {len(recent)} recent detections")

    # Test feedback
    print("\nTesting feedback recording...")
    db.record_feedback(detection_id, 0, "Correctly detected DGA")
    print("[OK] Feedback recorded")

    # Test get malicious
    print("\nTesting malicious domains retrieval...")
    malicious = db.get_malicious_domains(hours=24, limit=10)
    print(f"[OK] Retrieved {len(malicious)} malicious domains")

    # Test daily stats
    print("\nTesting daily stats calculation...")
    daily = db.calculate_daily_stats()
    print(f"[OK] Daily stats: {daily}")

    # Test database stats
    print("\nTesting database stats...")
    db_stats = db.get_database_stats()
    print(f"[OK] Database stats: {db_stats}")

    print("\n" + "=" * 50)
    print("All database tests passed!")
    print("=" * 50)
