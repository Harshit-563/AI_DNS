"""
API Service for DNS Threat Detection
Flask-based REST API for real-time threat classification
"""

from flask import Flask, request, jsonify
from datetime import datetime
import traceback

from core.fastflux_integration import IntegratedThreatClassifier
from core.config import APP_LOGGER, AUDIT_LOGGER, ERROR_LOGGER, log_classification, log_api_request, log_validation_error
from core.validators import RequestValidator
from core.db_service import ThreatDatabase

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

try:
    db = ThreatDatabase()
    APP_LOGGER.info("[OK] ThreatDatabase initialized successfully")
except Exception as e:
    ERROR_LOGGER.error(f"Failed to initialize database: {e}", exc_info=True)
    db = None

try:
    classifier = IntegratedThreatClassifier(model_path="models/dns_best_model.pkl")
    APP_LOGGER.info("[OK] Using newly retrained Random Forest model")
except Exception as e:
    ERROR_LOGGER.error(f"Failed to load retrained model: {e}", exc_info=True)
    classifier = IntegratedThreatClassifier(model_path=None)

# ============================================================================
# EXACT SNIFFER LOGIC REPLICATION
# ============================================================================
def get_sniffer_like_prediction(domain, ttl, unique_ip_count, query_rate):
    """Replicates the EXACT prediction overriding from the Tkinter sniffer"""
    result = classifier.classify(
        domain=domain, ttl=ttl, unique_ip_count=unique_ip_count, query_rate=query_rate
    )
    
    try:
        fastflux = classifier.detect_fastflux(
            domain=domain, ttl=ttl, unique_ip_count=unique_ip_count, query_rate=query_rate
        )
    except AttributeError:
        fastflux = {}

    prediction = result.get("final_prediction", "Benign")
    normalized = prediction if prediction != "Unknown" else "Benign"
    confidence = float(result.get("confidence", result.get("base_confidence", 0.5)))
    
    fastflux_analysis = result.get("fastflux_analysis") or {}
    if fastflux: fastflux_analysis.update(fastflux)
        
    ff_score = float(fastflux_analysis.get("fastflux_score", 0.0))
    is_fastflux = bool(fastflux_analysis.get("is_fastflux", False))
    
    # 1. Fast-Flux Override
    if is_fastflux:
        normalized = "fast_flux"
        confidence = 100 * ff_score

    # 2. Confidence Thresholds (Exact match to Tkinter UI)
    status = "Benign"
    if normalized == "Benign" and confidence >= 0.55:
        status = "Benign"
    elif normalized == "fast_flux":
        status = "fast_flux"
    elif normalized != "Benign" and confidence >= 0.6:
        status = normalized.upper()
    elif normalized != "Benign" and confidence >= 0.55:
        status = "SUSPICIOUS"
    else:
        status = "Benign"

    return {
        "label": normalized,
        "status": status,
        "confidence": confidence,
        "recommendation": "BLOCK" if normalized != "Benign" else "ALLOW",
        "probabilities": {
            "base_prediction": result.get("base_prediction"),
            "base_confidence": float(result.get("base_confidence", 0.5)),
            "final_class": result.get("final_class", 0),
        },
        "is_fastflux": is_fastflux,
        "ff_score": ff_score,
        "final_class_int": result.get("final_class", 0) 
    }

@app.route('/api/v1/classify', methods=['POST'])
def classify_domain():
    try:
        data = request.get_json()
        is_valid, error_msg, sanitized = RequestValidator.validate_classify_request(data)
        if not is_valid: return {'error': error_msg}, 400
        
        analysis = get_sniffer_like_prediction(
            sanitized['domain'], sanitized['ttl'], sanitized['unique_ip_count'], sanitized['query_rate']
        )
        
        if db:
            db.insert_threat_detection({
                'domain': sanitized['domain'],
                'final_class': analysis['final_class_int'],
                'confidence': analysis['confidence'],
                'ff_score': analysis['ff_score'],
                'is_fastflux': analysis['is_fastflux'],
                'source_ip': request.remote_addr,
                'model_version': '1.0'
            })
            
        return {
            'domain': sanitized['domain'],
            'label': analysis['label'],
            'status': analysis['status'],
            'confidence': analysis['confidence'],
            'recommendation': analysis['recommendation'],
            'is_fastflux': analysis['is_fastflux'],
            'ff_score': analysis['ff_score'],
            'timestamp': datetime.now().isoformat()
        }, 200
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/v1/health', methods=['GET'])
def health_check(): return {'status': 'OK'}, 200

if __name__ == '__main__':
    from waitress import serve
    print("Starting Waitress Production API on http://0.0.0.0:5000")
    serve(app, host='0.0.0.0', port=5000)