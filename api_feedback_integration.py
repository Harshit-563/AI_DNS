"""
API Integration for Feedback Learning System
New endpoints for GUI to mark false positives and trigger retraining
"""

from flask import request, jsonify
from functools import wraps
import logging

from feedback_learning_system import (
    FeedbackCollector, FeedbackLearningPipeline, VersionManager
)

logger = logging.getLogger(__name__)


# ============================================================================
# Initialize feedback system components
# ============================================================================

feedback_collector = FeedbackCollector(feedback_file="feedback_benign.csv")
feedback_pipeline = FeedbackLearningPipeline(retrain_threshold=100)
version_manager = VersionManager(model_dir="models")


# ============================================================================
# HELPER: API error handler
# ============================================================================

def api_error(message: str, code: int = 400):
    """Standard error response"""
    return {
        'status': 'error',
        'message': message,
        'timestamp': __import__('datetime').datetime.now().isoformat()
    }, code


def api_success(data: dict = None, code: int = 200):
    """Standard success response"""
    response = {
        'status': 'success',
        'timestamp': __import__('datetime').datetime.now().isoformat()
    }
    if data:
        response.update(data)
    return response, code


# ============================================================================
# ENDPOINT 1: Mark False Positive
# ============================================================================
# Add this to your Flask app in api_service.py

def register_feedback_endpoints(app):
    """
    Register feedback learning endpoints with Flask app
    
    Usage in api_service.py:
        from api_feedback_integration import register_feedback_endpoints
        register_feedback_endpoints(app)
    """
    
    @app.route('/api/v1/feedback/mark-false-positive', methods=['POST'])
    def mark_false_positive():
        """
        Mark a domain classification as false positive (should be benign)
        
        Request:
        {
            "domain": "example.com",
            "confidence_before": 0.85,
            "comment": "This is a legitimate domain",
            "current_model_version": "1.0"
        }
        
        Response:
        {
            "status": "success",
            "message": "False positive recorded",
            "feedback_count": 45,
            "retrain_suggested": false
        }
        """
        try:
            data = request.get_json()
            
            # Validate
            if not data or 'domain' not in data:
                return api_error("Domain is required", 400)
            
            domain = data['domain'].lower().strip()
            comment = data.get('comment', '')
            confidence = data.get('confidence_before')
            model_version = data.get('current_model_version', '1.0')
            
            # Collect feedback (label=0 for false positive = benign)
            success, msg = feedback_collector.collect_feedback(
                domain=domain,
                label=0,
                comment=comment,
                confidence_before=confidence,
                model_version=model_version
            )
            
            if not success:
                return api_error(msg, 400)
            
            # Check if retraining is triggered
            should_retrain, reason = feedback_pipeline.should_retrain()
            
            logger.info(f"False positive marked: {domain} (total: {feedback_collector.get_feedback_count()})")
            
            return api_success({
                'message': f'False positive recorded for {domain}',
                'feedback_count': feedback_collector.get_feedback_count(),
                'retrain_triggered': should_retrain,
                'retrain_reason': reason
            }), 200
        
        except Exception as e:
            logger.error(f"Error marking false positive: {e}", exc_info=True)
            return api_error(f"Internal server error: {str(e)}", 500)
    
    
    @app.route('/api/v1/feedback/mark-false-negative', methods=['POST'])
    def mark_false_negative():
        """
        Mark a domain as false negative (classified as benign but is actually DGA)
        
        Request:
        {
            "domain": "maliciouz.biz",
            "confidence_before": 0.20,
            "comment": "This domain is definitely malicious",
            "current_model_version": "1.0"
        }
        
        Response:
        {
            "status": "success",
            "message": "False negative recorded",
            "feedback_count": 46
        }
        """
        try:
            data = request.get_json()
            
            if not data or 'domain' not in data:
                return api_error("Domain is required", 400)
            
            domain = data['domain'].lower().strip()
            comment = data.get('comment', '')
            confidence = data.get('confidence_before')
            model_version = data.get('current_model_version', '1.0')
            
            # Collect feedback (label=1 for false negative = malicious/DGA)
            success, msg = feedback_collector.collect_feedback(
                domain=domain,
                label=1,
                comment=comment,
                confidence_before=confidence,
                model_version=model_version
            )
            
            if not success:
                return api_error(msg, 400)
            
            logger.info(f"False negative marked: {domain}")
            
            return api_success({
                'message': f'False negative recorded for {domain}',
                'feedback_count': feedback_collector.get_feedback_count()
            }), 200
        
        except Exception as e:
            logger.error(f"Error marking false negative: {e}", exc_info=True)
            return api_error(f"Internal server error", 500)
    
    
    @app.route('/api/v1/feedback/status', methods=['GET'])
    def feedback_status():
        """
        Get feedback system status and statistics
        
        Response:
        {
            "status": "success",
            "feedback_count": 45,
            "retrain_threshold": 100,
            "retrain_progress": "45 / 100 (45%)",
            "retrain_suggested": false,
            "latest_feedback": [ ... ]
        }
        """
        try:
            count = feedback_collector.get_feedback_count()
            threshold = feedback_pipeline.retrain_threshold
            should_retrain, reason = feedback_pipeline.should_retrain()
            latest = feedback_collector.get_latest_feedback(5)
            
            return api_success({
                'feedback_count': count,
                'retrain_threshold': threshold,
                'retrain_progress': f"{count} / {threshold} ({int(count/threshold*100)}%)",
                'retrain_suggested': should_retrain,
                'retrain_reason': reason if should_retrain else None,
                'latest_feedback_count': len(latest),
                'latest_feedback': latest.to_dict('records') if len(latest) > 0 else []
            }), 200
        
        except Exception as e:
            logger.error(f"Error getting feedback status: {e}")
            return api_error(f"Internal server error", 500)
    
    
    @app.route('/api/v1/feedback/retrain', methods=['POST'])
    def trigger_retraining():
        """
        Manually trigger model retraining
        
        Optional body:
        {
            "force": true,  # Ignore threshold
            "notes": "User-initiated retraining"
        }
        
        Response:
        {
            "status": "success",
            "message": "Retraining started",
            "job_id": "retrain_20260321_1430",
            "estimated_duration": "5-10 minutes"
        }
        """
        try:
            data = request.get_json() or {}
            force = data.get('force', False)
            notes = data.get('notes', 'Manual trigger')
            
            # Check if retraining is allowed
            should_retrain, reason = feedback_pipeline.should_retrain()
            if not should_retrain and not force:
                return api_success({
                    'message': f'Retraining not triggered: {reason}',
                    'retraining_executed': False
                }), 200
            
            # Run full pipeline
            logger.info(f"Starting retraining: {notes}")
            results = feedback_pipeline.run_full_pipeline()
            
            if results['success']:
                return api_success({
                    'message': 'Retraining completed successfully',
                    'version': results.get('model_version'),
                    'accuracy': results.get('metrics', {}).get('accuracy'),
                    'f1': results.get('metrics', {}).get('f1'),
                    'feedback_count': results.get('feedback_count'),
                    'steps_completed': results.get('steps_completed')
                }), 200
            else:
                return api_error(
                    f"Retraining failed: {results.get('error')}",
                    500
                )
        
        except Exception as e:
            logger.error(f"Error triggering retraining: {e}", exc_info=True)
            return api_error(f"Internal server error", 500)
    
    
    @app.route('/api/v1/models/versions', methods=['GET'])
    def get_model_versions():
        """
        Get all model versions and their metrics
        
        Response:
        {
            "status": "success",
            "versions": [
                {
                    "version": "v1",
                    "timestamp": "2026-03-20T10:30:45",
                    "accuracy": 1.0,
                    "f1": 1.0,
                    "feedback_count": 0
                },
                ...
            ]
        }
        """
        try:
            history = version_manager.get_version_history()
            
            return api_success({
                'versions': history.to_dict('records') if len(history) > 0 else []
            }), 200
        
        except Exception as e:
            logger.error(f"Error getting versions: {e}")
            return api_error("Internal server error", 500)
    
    
    @app.route('/api/v1/models/rollback', methods=['POST'])
    def rollback_model():
        """
        Rollback to a previous model version
        
        Request:
        {
            "version": "v1",
            "reason": "v2 has lower accuracy"
        }
        
        Response:
        {
            "status": "success",
            "message": "Rolled back to v1",
            "new_active_version": "v1"
        }
        """
        try:
            data = request.get_json()
            
            if not data or 'version' not in data:
                return api_error("Version is required", 400)
            
            version = data['version']
            reason = data.get('reason', 'User-initiated rollback')
            
            # Perform rollback
            success = version_manager.rollback_to_version(version)
            
            if success:
                logger.info(f"Rollback to {version}: {reason}")
                return api_success({
                    'message': f'Successfully rolled back to {version}',
                    'new_active_version': version
                }), 200
            else:
                return api_error(f"Rollback to {version} failed", 400)
        
        except Exception as e:
            logger.error(f"Error during rollback: {e}")
            return api_error("Internal server error", 500)
    
    
    logger.info("[OK] Feedback learning endpoints registered")


# ============================================================================
# Integration with existing api_service.py
# ============================================================================

INTEGRATION_SNIPPET = """
# Add to api_service.py after app initialization:

from api_feedback_integration import register_feedback_endpoints

# Register feedback endpoints
register_feedback_endpoints(app)

# Also add to the health endpoint:
@app.route('/api/v1/health', methods=['GET'])
def health():
    return {
        'status': 'OK',
        'feedback_system': 'enabled',
        'feedback_count': feedback_collector.get_feedback_count(),
        ...
    }, 200
"""

if __name__ == "__main__":
    print(INTEGRATION_SNIPPET)
