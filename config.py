"""
Configuration and logging setup for DNS threat detection system
Production-grade logging with file rotation and multiple handlers
"""

import logging
import logging.handlers
from pathlib import Path
from dataclasses import dataclass


# Create logs directory if it doesn't exist
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)


@dataclass
class ProductionConfig:
    """Production configuration for DNS threat detection"""
    
    # Model
    MODEL_PATH = "models/dns_rf_model.pkl"
    FEATURE_SET = 7  # Use 7 features (will be 14 after retraining)
    
    # Fast Flux Detection (tunable)
    FF_THRESHOLD = 0.6
    FF_DOMAIN_WEIGHT = 0.4
    FF_NETWORK_WEIGHT = 0.6
    
    # Logging
    LOG_LEVEL = logging.INFO
    APP_LOG_FILE = str(LOG_DIR / "dns_threat.log")
    AUDIT_LOG_FILE = str(LOG_DIR / "dns_threat_audit.log")
    ERROR_LOG_FILE = str(LOG_DIR / "dns_threat_error.log")
    
    # Validation
    DOMAIN_MAX_LENGTH = 253
    TTL_MIN = 0
    TTL_MAX = 2147483647
    MAX_IPS = 10000
    
    # API
    API_HOST = "0.0.0.0"
    API_PORT = 5000
    API_TIMEOUT = 5  # seconds
    
    # Database
    DB_PATH = "threat_detection.db"
    
    # Performance
    BATCH_SIZE = 1000
    CACHE_SIZE = 1000000


def setup_file_handler(log_file: str, formatter: logging.Formatter, level=logging.INFO):
    """Create file handler with rotation"""
    handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,  # Keep 5 backup files
    )
    handler.setLevel(level)
    handler.setFormatter(formatter)
    return handler


def setup_console_handler(formatter: logging.Formatter, level=logging.INFO):
    """Create console handler"""
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(formatter)
    return handler


def setup_logger(name: str, log_file: str, level=logging.INFO):
    """
    Setup a logger with both file and console output
    
    Args:
        name: Logger name
        log_file: Path to log file
        level: Logging level
        
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False  # Don't propagate to root logger
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Add file handler
    file_handler = setup_file_handler(log_file, formatter, level)
    logger.addHandler(file_handler)
    
    # Add console handler for INFO and above
    console_handler = setup_console_handler(formatter, logging.INFO)
    logger.addHandler(console_handler)
    
    return logger


def setup_audit_logger(name: str = "dns_audit"):
    """
    Setup audit logger for critical operations
    Logs user actions, model predictions, feedback
    """
    log_file = str(LOG_DIR / "dns_threat_audit.log")
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers.clear()
    
    # Audit format: timestamp, action, domain, result
    formatter = logging.Formatter(
        '%(asctime)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler = setup_file_handler(log_file, formatter, logging.INFO)
    logger.addHandler(file_handler)
    
    return logger


# Initialize loggers at module import
APP_LOGGER = setup_logger("dns_threat", ProductionConfig.APP_LOG_FILE)
AUDIT_LOGGER = setup_audit_logger("dns_audit")
ERROR_LOGGER = setup_logger("dns_error", ProductionConfig.ERROR_LOG_FILE, logging.ERROR)


# Example usage functions
def log_classification(domain: str, final_class: int, confidence: float, ff_score: float):
    """Log a classification result for audit"""
    class_names = {0: "Benign", 1: "DGA", 2: "Fast-Flux", 3: "Suspicious"}
    AUDIT_LOGGER.info(
        f"CLASSIFY | domain={domain} | class={class_names.get(final_class, 'Unknown')} | confidence={confidence:.2f} | ff_score={ff_score:.2f}"
    )


def log_api_request(method: str, endpoint: str, domain: str = None):
    """Log API request"""
    msg = f"API {method} {endpoint}"
    if domain:
        msg += f" - domain={domain}"
    APP_LOGGER.info(msg)


def log_validation_error(domain: str, error: str):
    """Log validation error"""
    APP_LOGGER.warning(f"VALIDATION_ERROR | domain={domain} | error={error}")


def log_database_operation(operation: str, domain: str, result: str = "OK"):
    """Log database operation"""
    AUDIT_LOGGER.info(f"DB | {operation} | domain={domain} | {result}")


def log_error_with_context(error: Exception, context: str):
    """Log error with context"""
    ERROR_LOGGER.error(f"{context} - {str(error)}", exc_info=True)


if __name__ == "__main__":
    # Test logging setup
    print("Testing logging setup...\n")
    
    # Test app logger
    print("1. Testing APP_LOGGER:")
    APP_LOGGER.info("Test info message")
    APP_LOGGER.warning("Test warning message")
    APP_LOGGER.error("Test error message")
    print("   ✓ Check logs/dns_threat.log\n")
    
    # Test audit logger
    print("2. Testing AUDIT_LOGGER:")
    log_classification("example.com", 0, 0.95, 0.2)
    log_api_request("POST", "/api/v1/classify", "malware.cc")
    log_validation_error("invalid..domain", "contains consecutive dots")
    print("   ✓ Check logs/dns_threat_audit.log\n")
    
    # Test error logger
    print("3. Testing ERROR_LOGGER:")
    try:
        raise ValueError("Test error")
    except Exception as e:
        log_error_with_context(e, "Test context")
    print("   ✓ Check logs/dns_threat_error.log\n")
    
    print("✅ Logging setup complete!")
    print(f"\nLog files created in: {LOG_DIR}")
