"""
FEEDBACK LEARNING SYSTEM - DEPLOYMENT & SAFEGUARDS GUIDE

Production-ready threat detection model improvement system
with comprehensive safety mechanisms to prevent data poisoning
"""

# ============================================================================
# TABLE OF CONTENTS
# ============================================================================
"""
1. QUICK START
2. SYSTEM ARCHITECTURE
3. SAFETY MECHANISMS
4. DEPLOYMENT CHECKLIST
5. INTEGRATION STEPS
6. MONITORING & METRICS
7. TROUBLESHOOTING
8. BEST PRACTICES
"""


# ============================================================================
# 1. QUICK START
# ============================================================================

QUICK_START = """
QUICK START GUIDE

Step 1: Initialize the feedback system
    from feedback_learning_system import FeedbackLearningPipeline
    pipeline = FeedbackLearningPipeline(retrain_threshold=100)

Step 2: Integrate API endpoints
    # In api_service.py
    from api_feedback_integration import register_feedback_endpoints
    register_feedback_endpoints(app)

Step 3: Integrate GUI feedback panel
    # In dns_sniffer_gui.py
    from gui_feedback_integration import FeedbackPanel
    feedback_panel = FeedbackPanel(root, api_url="http://localhost:5000")

Step 4: Start collecting feedback
    # Users click "Mark False Positive" in GUI
    # Feedback is automatically saved to feedback_benign.csv

Step 5: Monitor retraining progress
    # POST /api/v1/feedback/retrain
    # Check /api/v1/feedback/status for progress

Step 6: Verify improvements
    # Compare model versions in /api/v1/models/versions
    # Rollback if needed with /api/v1/models/rollback
"""


# ============================================================================
# 2. SYSTEM ARCHITECTURE
# ============================================================================

SYSTEM_ARCHITECTURE = """
SYSTEM ARCHITECTURE

┌─────────────────────────────────────────────────────────────────┐
│                    DNS THREAT DETECTION SYSTEM                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐                           ┌─────────────────┐ │
│  │   GUI/API    │                           │  Model Training │ │
│  │   (Flask)    │                           │  (Offline)      │ │
│  └──────┬───────┘                           └────────┬────────┘ │
│         │                                            │          │
│         │ User marks false positive                  │          │
│         ├─────────────────────────────────────────→  │          │
│         │                                            │          │
│         │  1. FeedbackCollector → feedback_benign.csv          │
│         │  2. FeedbackDataset → Validate & Clean               │
│         │  3. ModelRetrainer → Merge datasets                  │
│         │  4. Train new model (RF/XGBoost)                     │
│         │  5. VersionManager → Save dns_model_vX.pkl           │
│         │  6. FeedbackMonitor → Track improvements             │
│         │                                            │          │
│         │  ┌──────────────────────────────────────┐ │          │
│         │  │  SAFETY SAFEGUARDS                   │ │          │
│         │  ├──────────────────────────────────────┤ │          │
│         │  │ • Dedup domains                      │ │          │
│         │  │ • Validate features (25 features)    │ │          │
│         │  │ • Check for NaN values               │ │          │
│         │  │ • Limit feedback ratio (max 10%)     │ │          │
│         │  │ • Balanced dataset requirement       │ │          │
│         │  │ • Detect poisoning attempts          │ │          │
│         │  │ • Monitor model overfitting          │ │          │
│         │  │ • Version control & rollback         │ │          │
│         │  └──────────────────────────────────────┘ │          │
│         │                                            │          │
│         ← Updated model ready (or rollback available) ←         │
│         │                                                       │
│  ┌──────┴───────┐                           ┌─────────────────┐ │
│  │   Classify   │←──────────────────────────│  Load Best Model│ │
│  │  Domains     │      dns_best_model.pkl   │  (Version API)  │ │
│  └──────────────┘                           └─────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
"""


# ============================================================================
# 3. SAFETY MECHANISMS
# ============================================================================

SAFETY_MECHANISMS = """
SAFETY SAFEGUARDS AGAINST POISONING & OVERFITTING

1. DEDUPLICATION
   - Prevents same domain from being marked multiple times
   - Keeps only first occurrence (earliest feedback)
   - Impact: Reduces bias toward frequently marked domains

2. FEATURE VALIDATION
   - All 25 features must be extractable
   - Max 5 NaN/missing values allowed per sample
   - Invalid entries automatically removed
   - Impact: Maintains training data quality

3. DATASET BALANCING
   - Feedback is capped at 10% of original dataset
   - Example: If 5000 benign domains, max 500 feedback entries
   - Maintains benign:DGA ratio
   - Impact: Prevents feedback data from overwhelming original data

4. OVERFITTING DETECTION
   - Compares train accuracy vs test accuracy
   - Flags if difference > 10%
   - Suggests manual review if overfitting detected
   - Impact: Catches potential generalization failures

5. POISONING DETECTION (Heuristic)
   - Monitors for rapid feedback submissions (>50 in 1 hour)
   - Tracks feedback from same user/IP
   - Flags if marking legitimate domains as DGA
   - Impact: Early warning of coordinated attacks

6. MODEL VERSIONING
   - Every retrain creates new version (v1, v2, v3, ...)
   - Old models never deleted
   - Instant rollback to previous version
   - Impact: Can revert if new model degrades performance

7. THRESHOLD-BASED RETRAINING
   - Retrain only when feedback ≥ threshold (default: 100)
   - Prevents retraining on too-small feedback sets
   - Impact: Each model is more statistically significant

8. CONFIDENCE TRACKING
   - Records model confidence before user marked it
   - Tracks which domains are most problematic
   - Identifies systematic biases
   - Impact: Understand root causes of false positives
"""


# ============================================================================
# 4. DEPLOYMENT CHECKLIST
# ============================================================================

DEPLOYMENT_CHECKLIST = """
DEPLOYMENT CHECKLIST

PRE-DEPLOYMENT
  □ Ensure api_service.py is running (Flask app)
  □ Ensure threat_detection.db exists (SQLite)
  □ Verify models/ directory with dns_best_model.pkl exists
  □ Confirm Datasets directories are accessible
  □ Check Python dependencies: scikit-learn, xgboost, pandas, joblib

API ENDPOINT REGISTRATION
  □ Copy api_feedback_integration.py to project root
  □ Add to api_service.py:
      from api_feedback_integration import register_feedback_endpoints
      register_feedback_endpoints(app)
  □ Restart Flask app
  □ Test: GET http://localhost:5000/api/v1/feedback/status

GUI INTEGRATION
  □ Copy gui_feedback_integration.py to project root
  □ Update dns_sniffer_gui.py to import FeedbackPanel:
      from gui_feedback_integration import FeedbackPanel
  □ Add to __init__:
      self.feedback_panel = FeedbackPanel(self.root, api_url=self.api_url)
  □ Update classification display method:
      self.feedback_panel.set_current_classification(domain, pred, conf)
  □ Test: Run GUI and verify "Mark False Positive" button works

FEEDBACK COLLECTION
  □ Create feedback_benign.csv (auto-created on first use)
  □ Verify feedback is being saved
  □ Create monitoring dashboard (optional)
  □ Set up logging alerts

RETRAINING TRIGGERS
  □ Set retrain_threshold (recommend: start at 100)
  □ Configure automatic retraining (optional)
  □ Set manual retraining schedule (e.g., weekly)
  □ Create monitoring for retraining jobs

MONITORING & ALERTS
  □ Set up logging for feedback_learning_system.py
  □ Monitor API endpoints for errors
  □ Track feedback_count growth
  □ Alert when threshold is reached
  □ Alert on retraining failures

DOCUMENTATION
  □ Document feedback guidelines for users
  □ Explain when to mark false positives
  □ Create runbooks for retraining procedures
  □ Document rollback procedures
"""


# ============================================================================
# 5. INTEGRATION STEPS (DETAILED)
# ============================================================================

INTEGRATION_STEPS = """
DETAILED INTEGRATION STEPS

STEP 1: Update api_service.py
────────────────────────────────────────────────────────────────

Add imports at the top:
    from api_feedback_integration import register_feedback_endpoints

After app initialization (after "app = Flask(__name__)"):
    # Initialize feedback system
    register_feedback_endpoints(app)

Test the new endpoints:
    curl -X GET http://localhost:5000/api/v1/feedback/status
    
Expected response:
    {
        "status": "success",
        "feedback_count": 0,
        "retrain_threshold": 100,
        "retrain_progress": "0 / 100 (0%)"
    }


STEP 2: Update dns_sniffer_gui.py
────────────────────────────────────────────────────────────────

Add import:
    from gui_feedback_integration import FeedbackPanel

In __init__ method, after self.build_ui() call:
    # Initialize feedback panel
    self.feedback_panel = FeedbackPanel(
        parent_widget=self.root,
        api_url=self.api_url
    )

When displaying a classification result, update the panel:
    # After getting classification result
    self.feedback_panel.set_current_classification(
        domain=domain,
        prediction=result['final_prediction'],
        confidence=result['confidence']
    )

Example location (in your packet processing callback):
    result = self.classifier.classify(domain, ttl, ips, rate)
    # ... display result ...
    self.feedback_panel.set_current_classification(
        domain,
        result['final_prediction'],
        result['confidence']
    )


STEP 3: Create Configuration File (Optional)
────────────────────────────────────────────────────────────────

Create feedback_config.py:

    FEEDBACK_LEARNING_CONFIG = {
        'enabled': True,
        'feedback_file': 'feedback_benign.csv',
        'retrain_threshold': 100,
        'max_feedback_ratio': 0.1,  # 10% max
        'model_dir': 'models',
        'enable_poisoning_detection': True,
        'enable_overfitting_detection': True,
        'auto_retrain': False,  # Manual retrain only
        'retrain_schedule': 'weekly',  # Or 'manual', 'daily'
    }


STEP 4: Enable Logging
────────────────────────────────────────────────────────────────

In your main config.py or logging setup:
    logging.getLogger('feedback_learning_system').setLevel(logging.INFO)
    
This enables debug output from the feedback system.


STEP 5: Create Monitoring Dashboard (Optional)
────────────────────────────────────────────────────────────────

Create feedback_dashboard.py:

    import streamlit as st
    import pandas as pd
    import requests
    
    st.title("Feedback Learning Dashboard")
    
    # Feedback Status
    response = requests.get("http://localhost:5000/api/v1/feedback/status")
    status = response.json()
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Feedback Count", status['feedback_count'])
    col2.metric("Retrain Threshold", status['retrain_threshold'])
    col3.metric("Progress", f"{status['feedback_count'] / status['retrain_threshold'] * 100:.0f}%")
    
    # Model Versions
    versions_response = requests.get("http://localhost:5000/api/v1/models/versions")
    versions = versions_response.json()['versions']
    
    st.dataframe(pd.DataFrame(versions))
    
    # Trigger Retraining
    if st.button("Trigger Retraining Now"):
        ret_response = requests.post("http://localhost:5000/api/v1/feedback/retrain")
        st.success(ret_response.json()['message'])

Run with:
    streamlit run feedback_dashboard.py
"""


# ============================================================================
# 6. MONITORING & METRICS
# ============================================================================

MONITORING_METRICS = """
KEY METRICS TO MONITOR

1. FEEDBACK GROWTH
   - Metric: feedback_count
   - Goal: Steady growth (e.g., 10-20 per day)
   - Alert: No feedback for >7 days (might indicate lack of engagement)

2. FALSE POSITIVE REDUCTION
   - Before: Benign domains classified as DGA
   - After: Same domains correctly classified as Benign
   - Track: % of previous false positives now correct

3. MODEL ACCURACY IMPROVEMENT
   - Track accuracy over versions
   - Goal: Should improve with each retrain (or stay same)
   - Alert: If new version has lower accuracy

4. PRECISION & RECALL BALANCE
   - Before: May have high false positive rate
   - After: Reduced false positives, maintained recall
   - Goal: Improve precision without sacrificing recall

5. OVERFITTING INDICATORS
   - Train accuracy vs Test accuracy gap
   - Goal: Gap should be < 10%
   - Alert: If gap > 15%

6. RETRAINING FREQUENCY
   - Track: How often models are retrained
   - Goal: When threshold is met naturally (not forced)
   - Alert: If forced retraining needed (indicates issues)

7. ROLLBACK FREQUENCY
   - Track: How many times rollback was needed
   - Goal: Minimal (ideally 0)
   - Alert: If multiple rollbacks (indicates poor feedback quality)

8. FEEDBACK QUALITY SCORE
   - Combine:
      - Dedup rate (should be low, <5%)
      - Feature validity (should be high, >95%)
      - Contributing to accuracy improvement
   - Goal: Quality score > 0.8


MONITORING SQL QUERIES

-- Check feedback growth over time
SELECT DATE(timestamp), COUNT(*) as feedback_per_day
FROM feedback_benign.csv
GROUP BY DATE(timestamp)
ORDER BY timestamp DESC;

-- Check which domains are most problematic
SELECT domain, COUNT(*) as marked_count
FROM feedback_benign.csv
GROUP BY domain
ORDER BY marked_count DESC
LIMIT 10;

-- Model version comparison
SELECT version, accuracy, f1, timestamp
FROM model_metrics
ORDER BY timestamp DESC
LIMIT 5;

-- Check for possible poisoning
SELECT * FROM feedback_benign.csv
WHERE timestamp >= datetime('now', '-1 day')
ORDER BY timestamp;
"""


# ============================================================================
# 7. TROUBLESHOOTING
# ============================================================================

TROUBLESHOOTING = """
TROUBLESHOOTING GUIDE

PROBLEM: "Feedback is not being saved"
SOLUTION:
  1. Check if feedback_benign.csv is writable
  2. Verify API is running: GET /api/v1/health
  3. Check API logs for errors
  4. Ensure feature extraction is working
  5. Check disk space

PROBLEM: "Retraining fails with 'Module not found' error"
SOLUTION:
  1. Ensure scikit-learn, xgboost, pandas installed
  2. Run: pip install -r requirements.txt
  3. Check Python path is correct
  4. Verify Datasets/ directory exists and is readable

PROBLEM: "Model accuracy decreased after retrain"
SOLUTION:
  1. Check feedback quality - any obvious spam?
  2. Verify dataset balance (benign:DGA ratio)
  3. Check for outliers or corrupted features
  4. Use rollback: POST /api/v1/models/rollback {"version": "v1"}
  5. Review feedback comments for issues

PROBLEM: "Too many false positives still occurring"
SOLUTION:
  1. Collect more feedback (ensure threshold reached)
  2. Verify feedback is accurate (not user errors)
  3. Consider increasing max_feedback_ratio
  4. Retrain more frequently
  5. Check if specific domain type is problematic

PROBLEM: "Retrain takes too long (>30 minutes)"
SOLUTION:
  1. Reduce max_feedback_ratio (currently 10%)
  2. Limit dataset size:
     benign_sample = benign_domains[:3000]  # Reduce from 5000
     dga_sample = dga_domains[:3000]
  3. Use fewer estimators in model:
     RandomForestClassifier(n_estimators=100)  # Instead of 200
  4. Use faster model: XGBoost instead of Random Forest
  5. Disable cross-validation

PROBLEM: "API endpoint returns 500 error"
SOLUTION:
  1. Check Flask app logs
  2. Verify database connection
  3. Ensure models/ directory exists
  4. Check for Python exceptions in logs
  5. Restart Flask app

PROBLEM: "Can't rollback to previous version"
SOLUTION:
  1. Verify model file exists: models/dns_model_v1.pkl
  2. Check file is not corrupted: joblib.load("models/dns_model_v1.pkl")
  3. Ensure write permissions to models/ directory
  4. Check available disk space
"""


# ============================================================================
# 8. BEST PRACTICES
# ============================================================================

BEST_PRACTICES = """
BEST PRACTICES FOR FEEDBACK LEARNING

FEEDBACK QUALITY
✓ Mark only obvious false positives (high confidence)
✓ Include descriptive comments when marking
✓ Wait until you have 100+ feedback entries before retraining
✓ Review marked domains manually before large retraining
✓ Don't mark domains you're unsure about

RETRAINING STRATEGY
✓ Start with low threshold (50-100) to test
✓ Monitor each version for accuracy improvement
✓ Retrain weekly or when threshold is reached
✓ Don't retrain more than once per day
✓ Always test new version before going to production

SAFETY PRACTICES
✓ Keep old model versions (never delete)
✓ Always have a rollback plan
✓ Monitor for poisoning attempts
✓ Log all retraining events
✓ Review feedback at regular intervals
✓ Set up alerts for anomalies
✓ Maintain separate monitor/audit logs

DATASET MANAGEMENT
✓ Backup feedback_benign.csv regularly
✓ Backup model files regularly
✓ Document data lineage (which feedback from when)
✓ Maintain version history CSV
✓ Archive old datasets with version numbers

USER GUIDELINES
✓ Only mark domains you're confident about
✓ Provide context in comments
✓ Report suspicious marking patterns
✓ Don't mark for malicious purposes
✓ Review system feedback regularly

OPERATIONAL PROCEDURES
✓ Schedule regular retraining (e.g., weekly)
✓ Monitor feedback quality metrics daily
✓ Review suggestions for rollback
✓ Document any manual interventions
✓ Share improvements with team
✓ Update runbooks based on learnings

TECHNICAL DEBT
✓ Periodically review feedback comments for patterns
✓ Consolidate highly similar domains in feedback
✓ Update feature extraction if new patterns emerge
✓ Archive old feedback after retraining
✓ Optimize dataset size based on performance
"""


# ============================================================================
# EXPORT ALL GUIDES
# ============================================================================

if __name__ == "__main__":
    guides = {
        'QUICK_START': QUICK_START,
        'ARCHITECTURE': SYSTEM_ARCHITECTURE,
        'SAFETY': SAFETY_MECHANISMS,
        'CHECKLIST': DEPLOYMENT_CHECKLIST,
        'INTEGRATION': INTEGRATION_STEPS,
        'MONITORING': MONITORING_METRICS,
        'TROUBLESHOOTING': TROUBLESHOOTING,
        'BEST_PRACTICES': BEST_PRACTICES,
    }
    
    print("=" * 80)
    print("FEEDBACK LEARNING SYSTEM - DEPLOYMENT GUIDE")
    print("=" * 80)
    
    for title, guide in guides.items():
        print(f"\n{'='*80}")
        print(f"{title}")
        print(f"{'='*80}")
        print(guide)
