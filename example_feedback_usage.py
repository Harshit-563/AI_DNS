"""
EXAMPLE: Complete Feedback Learning System Integration
Shows how to use all components together
"""

import logging
from datetime import datetime
from feedback_learning_system import (
    FeedbackCollector,
    FeedbackDataset,
    ModelRetrainer,
    VersionManager,
    FeedbackMonitor,
    FeedbackLearningPipeline
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# EXAMPLE 1: BASIC FEEDBACK COLLECTION
# ============================================================================

def example_feedback_collection():
    """Example: Collect feedback from users"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 1: BASIC FEEDBACK COLLECTION")
    logger.info("="*80)
    
    collector = FeedbackCollector(feedback_file="feedback_benign.csv")
    
    # Simulate user marking domains as false positives
    test_domains = [
        {
            "domain": "mycompany.com",
            "comment": "This is our legitimate company domain",
            "confidence_before": 0.92,
        },
        {
            "domain": "internal.example.com",
            "comment": "Internal company site, should be benign",
            "confidence_before": 0.88,
        },
        {
            "domain": "trusted-vendor.org",
            "comment": "Trusted third-party vendor",
            "confidence_before": 0.85,
        },
    ]
    
    logger.info(f"\nCollecting {len(test_domains)} feedback entries...")
    
    for domain_data in test_domains:
        success, msg = collector.collect_feedback(
            domain=domain_data["domain"],
            label=0,  # 0 = False Positive (actually benign)
            comment=domain_data["comment"],
            confidence_before=domain_data["confidence_before"],
            model_version="1.0"
        )
        
        if success:
            logger.info(f"✓ {domain_data['domain']:30s} -> {msg}")
        else:
            logger.error(f"✗ {domain_data['domain']:30s} -> {msg}")
    
    total = collector.get_feedback_count()
    logger.info(f"\nTotal feedback entries: {total}")
    
    return collector


# ============================================================================
# EXAMPLE 2: VALIDATE AND CLEAN FEEDBACK
# ============================================================================

def example_validate_feedback():
    """Example: Validate feedback quality"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 2: VALIDATE AND CLEAN FEEDBACK")
    logger.info("="*80)
    
    dataset = FeedbackDataset(feedback_file="feedback_benign.csv")
    
    # Validate and clean
    logger.info("Validating feedback dataset...")
    df_clean, stats = dataset.validate_and_clean()
    
    logger.info("\nValidation Statistics:")
    logger.info(f"  Total entries:        {stats['total']}")
    logger.info(f"  Valid entries:        {stats['valid']}")
    logger.info(f"  Duplicates removed:   {stats['duplicates']}")
    logger.info(f"  Invalid entries:      {stats['invalid']}")
    logger.info(f"  Incomplete features:  {stats['incomplete_features']}")
    
    if len(df_clean) > 0:
        logger.info(f"\nSample valid entries:")
        logger.info(df_clean[['domain', 'label', 'timestamp']].head(3).to_string())
    
    return df_clean, stats


# ============================================================================
# EXAMPLE 3: MERGE DATASETS
# ============================================================================

def example_merge_datasets():
    """Example: Merge feedback with original datasets"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 3: MERGE FEEDBACK WITH ORIGINAL DATASETS")
    logger.info("="*80)
    
    dataset = FeedbackDataset(feedback_file="feedback_benign.csv")
    
    logger.info("Merging feedback with original datasets...")
    logger.info("This extracts 25 features for each domain...\n")
    
    X, y = dataset.merge_with_original_datasets(
        benign_dir=None,
        dga_file="Datasets/dga_data.csv/dga_data.csv",
        max_feedback_ratio=0.1
    )
    
    logger.info(f"\nMerged dataset:")
    logger.info(f"  Shape:           {X.shape}")
    logger.info(f"  Benign samples:  {len(y[y==0])}")
    logger.info(f"  DGA samples:     {len(y[y==1])}")
    logger.info(f"  Features:        {', '.join(X.columns[:5])}... ({len(X.columns)} total)")
    logger.info(f"  Class balance:   {(y==0).sum() / len(y) * 100:.1f}% benign, {(y==1).sum() / len(y) * 100:.1f}% DGA")
    
    return X, y


# ============================================================================
# EXAMPLE 4: RETRAIN MODEL
# ============================================================================

def example_retrain_model(X, y):
    """Example: Retrain threat detection model"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 4: RETRAIN MODEL")
    logger.info("="*80)
    
    retrainer = ModelRetrainer(model_dir="models")
    
    logger.info("Training Random Forest model...")
    logger.info("(This may take 2-3 minutes)\n")
    
    model_dict, metrics = retrainer.retrain_model(
        X=X,
        y=y,
        test_size=0.2,
        model_type='random_forest'
    )
    
    logger.info(f"\nModel Performance Metrics:")
    logger.info(f"  Accuracy:         {metrics['accuracy']:.4f}")
    logger.info(f"  Precision:        {metrics['precision']:.4f}")
    logger.info(f"  Recall:           {metrics['recall']:.4f}")
    logger.info(f"  F1-Score:         {metrics['f1']:.4f}")
    logger.info(f"  AUC-ROC:          {metrics['roc_auc']:.4f}")
    logger.info(f"  Test Samples:     {metrics['test_samples']}")
    logger.info(f"  Train Samples:    {metrics['train_samples']}")
    
    # Check for overfitting
    if 'confusion_matrix' in metrics:
        cm = metrics['confusion_matrix']
        logger.info(f"\nConfusion Matrix:")
        logger.info(f"  True Negatives:   {cm[0][0]}")
        logger.info(f"  False Positives:  {cm[0][1]}")
        logger.info(f"  False Negatives:  {cm[1][0]}")
        logger.info(f"  True Positives:   {cm[1][1]}")
    
    return model_dict, metrics


# ============================================================================
# EXAMPLE 5: SAVE VERSIONED MODEL
# ============================================================================

def example_save_versioned_model(model_dict, metrics):
    """Example: Save model with version"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 5: SAVE VERSIONED MODEL")
    logger.info("="*80)
    
    retrainer = ModelRetrainer(model_dir="models")
    
    logger.info("Saving versioned model...")
    model_path, version = retrainer.save_versioned_model(
        model_dict=model_dict,
        metrics=metrics,
        version=None  # Auto-generate version
    )
    
    logger.info(f"\nModel saved:")
    logger.info(f"  Path:    {model_path}")
    logger.info(f"  Version: {version}")
    
    return version


# ============================================================================
# EXAMPLE 6: VERSION MANAGEMENT
# ============================================================================

def example_version_management(version, metrics):
    """Example: Manage model versions"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 6: VERSION MANAGEMENT")
    logger.info("="*80)
    
    version_mgr = VersionManager(model_dir="models")
    
    logger.info("Logging version to history...")
    version_mgr.log_version(
        version=version,
        model_type='random_forest',
        metrics=metrics,
        feedback_count=10,
        notes="Example retraining with feedback"
    )
    
    logger.info("\nVersion History:")
    history = version_mgr.get_version_history()
    
    if len(history) > 0:
        logger.info(history[['version', 'accuracy', 'f1', 'feedback_count']].to_string())
    else:
        logger.info("No version history available")


# ============================================================================
# EXAMPLE 7: FEEDBACK MONITORING
# ============================================================================

def example_feedback_monitoring():
    """Example: Monitor feedback impact"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 7: FEEDBACK MONITORING")
    logger.info("="*80)
    
    monitor = FeedbackMonitor()
    
    logger.info("Analyzing feedback impact...")
    analysis = monitor.analyze_feedback_impact(
        old_version="v1",
        new_version="v2"
    )
    
    logger.info(f"\nFeedback Impact Analysis:")
    logger.info(f"  Accuracy Improvement:  {analysis.get('accuracy_improvement', 0):.2%}")
    logger.info(f"  Precision Improvement: {analysis.get('precision_improvement', 0):.2%}")
    logger.info(f"  Recall Improvement:    {analysis.get('recall_improvement', 0):.2%}")
    logger.info(f"  F1 Improvement:        {analysis.get('f1_improvement', 0):.2%}")
    logger.info(f"  Evaluation:            {analysis.get('evaluation', 'N/A')}")
    
    # Detect poisoning
    logger.info("\nDetecting poisoning attempts...")
    suspicious = monitor.detect_poisoning_attempts()
    
    if suspicious:
        logger.warning(f"Found {len(suspicious)} suspicious activities:")
        for item in suspicious:
            logger.warning(f"  - {item}")
    else:
        logger.info("No suspicious activities detected ✓")


# ============================================================================
# EXAMPLE 8: COMPLETE PIPELINE
# ============================================================================

def example_complete_pipeline():
    """Example: Run complete feedback learning pipeline"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 8: COMPLETE PIPELINE (END-TO-END)")
    logger.info("="*80)
    
    pipeline = FeedbackLearningPipeline(
        feedback_file="feedback_benign.csv",
        retrain_threshold=5,  # Low threshold for demo
        model_dir="models"
    )
    
    logger.info("Checking if retraining is needed...")
    should_retrain, reason = pipeline.should_retrain()
    logger.info(f"Should retrain: {should_retrain} ({reason})")
    
    if should_retrain:
        logger.info("\nRunning complete pipeline...")
        results = pipeline.run_full_pipeline()
        
        logger.info(f"\nPipeline Results:")
        logger.info(f"  Success:        {results['success']}")
        logger.info(f"  Steps:          {len(results.get('steps_completed', []))}")
        logger.info(f"  Model Version:  {results.get('model_version', 'N/A')}")
        logger.info(f"  Feedback Count: {results.get('feedback_count', 'N/A')}")
        
        if results.get('metrics'):
            metrics = results['metrics']
            logger.info(f"\nModel Metrics:")
            logger.info(f"  Accuracy: {metrics.get('accuracy', 0):.4f}")
            logger.info(f"  F1-Score: {metrics.get('f1', 0):.4f}")
    else:
        logger.info("Threshold not reached. Continue collecting feedback.")


# ============================================================================
# EXAMPLE 9: ERROR HANDLING
# ============================================================================

def example_error_handling():
    """Example: Handle errors gracefully"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 9: ERROR HANDLING")
    logger.info("="*80)
    
    collector = FeedbackCollector()
    
    # Try invalid domain
    logger.info("Testing error handling with invalid inputs...\n")
    
    test_cases = [
        ("", None, "Empty domain name"),
        ("a" * 300, None, "Domain name too long"),
        ("../malicious", None, "Path traversal attempt"),
    ]
    
    for domain, comment, description in test_cases:
        success, msg = collector.collect_feedback(
            domain=domain,
            label=0,
            comment=comment
        )
        
        status = "✓" if success else "✗"
        logger.info(f"{status} {description:30s} -> {msg[:50]}")


# ============================================================================
# MAIN RUNNER
# ============================================================================

def main():
    """Run all examples"""
    logger.info("\n" + "="*80)
    logger.info("FEEDBACK LEARNING SYSTEM - COMPLETE EXAMPLES")
    logger.info("="*80 + "\n")
    
    try:
        # Example 1: Collection
        # collector = example_feedback_collection()
        
        # Example 2: Validation
        # df_clean, stats = example_validate_feedback()
        
        # Example 3: Merge datasets
        # X, y = example_merge_datasets()
        
        # Example 4: Retrain
        # model_dict, metrics = example_retrain_model(X, y)
        
        # Example 5: Save versioned
        # version = example_save_versioned_model(model_dict, metrics)
        
        # Example 6: Version management
        # example_version_management(version, metrics)
        
        # Example 7: Monitoring
        # example_feedback_monitoring()
        
        # Example 8: Complete pipeline
        example_complete_pipeline()
        
        # Example 9: Error handling
        example_error_handling()
        
        logger.info("\n" + "="*80)
        logger.info("EXAMPLES COMPLETED")
        logger.info("="*80)
        logger.info("\nFor production use:")
        logger.info("  1. Integrate API endpoints (api_feedback_integration.py)")
        logger.info("  2. Integrate GUI panel (gui_feedback_integration.py)")
        logger.info("  3. Set up monitoring")
        logger.info("  4. Configure retraining schedule")
        logger.info("  5. Start collecting feedback from users")
    
    except Exception as e:
        logger.error(f"Error running examples: {e}", exc_info=True)


if __name__ == "__main__":
    main()
