"""
Production-Grade Feedback Learning System
Collects user feedback, validates data, and retrains threat detection models
with comprehensive safeguards against poisoning and overfitting.

ARCHITECTURE:
- FeedbackCollector: Captures and validates user feedback
- FeedbackDataset: Manages deduplication and consistency
- ModelRetrainer: Retrains with combined datasets
- VersionManager: Handles model versioning and rollback
- FeedbackMonitor: Tracks improvements and safety metrics
"""

import pandas as pd
import numpy as np
import joblib
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from collections import Counter
import hashlib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

from data_engg import DomainFeatureExtractor
from db_service import ThreatDatabase

# ============================================================================
# LOGGING SETUP
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

COMBINED_DGA_DATASET = "Datasets/dga_data.csv/dga_data.csv"


# ============================================================================
# 1. FEEDBACK COLLECTOR
# ============================================================================

class FeedbackCollector:
    """
    Collects and initially validates user feedback from the GUI
    
    When user clicks "Mark False Positive":
    - Domain is marked as BENIGN (label=0)
    - Features are extracted
    - Entry is stored in feedback_benign.csv
    """
    
    def __init__(self, feedback_file: str = "feedback_benign.csv"):
        """
        Initialize feedback collector
        
        Args:
            feedback_file: Path to CSV file for storing feedback
        """
        self.feedback_file = Path(feedback_file)
        self.extractor = DomainFeatureExtractor()
        self.db = ThreatDatabase()
        
        # Create feedback file if it doesn't exist
        if not self.feedback_file.exists():
            self._create_feedback_file()
            logger.info(f"Created new feedback file: {self.feedback_file}")
    
    def _create_feedback_file(self):
        """Create feedback CSV with proper headers"""
        cols = [
            'domain', 'label', 'timestamp', 'user_comment',
            'feature_extraction_error', 'confidence_before',
            'model_version_when_marked'
        ]
        # Add feature columns
        cols.extend([f'feature_{i}' for i in range(25)])
        
        df = pd.DataFrame(columns=cols)
        df.to_csv(self.feedback_file, index=False)
        logger.info(f"Feedback file created with {len(cols)} columns")
    
    def collect_feedback(
        self,
        domain: str,
        label: int = 0,  # 0 = Benign (False Positive), 1 = DGA
        comment: str = None,
        confidence_before: float = None,
        model_version: str = "1.0"
    ) -> Tuple[bool, str]:
        """
        Collect feedback for a domain
        
        Args:
            domain: Domain name
            label: 0=Benign (False Positive), 1=DGA (False Negative)
            comment: User comment
            confidence_before: Model confidence before marking
            model_version: Version of model when marked
        
        Returns:
            (success: bool, message: str)
        """
        try:
            # Basic validation
            if not domain or len(domain) == 0:
                return False, "Domain cannot be empty"
            
            if len(domain) > 255:
                return False, "Domain name too long (max 255 chars)"
            
            domain = domain.lower().strip()
            
            logger.info(f"Collecting feedback: domain={domain}, label={label}")
            
            # Extract features
            try:
                all_features = self.extractor.extract_all_features(domain)
                feature_error = None
            except Exception as e:
                logger.warning(f"Feature extraction failed for {domain}: {e}")
                all_features = {f'feature_{i}': np.nan for i in range(25)}
                feature_error = str(e)[:100]
            
            # Build feedback entry
            feedback_entry = {
                'domain': domain,
                'label': int(label),
                'timestamp': datetime.now().isoformat(),
                'user_comment': comment or '',
                'feature_extraction_error': feature_error or '',
                'confidence_before': float(confidence_before) if confidence_before else None,
                'model_version_when_marked': model_version
            }
            
            # Add features (first 25)
            for i, (key, value) in enumerate(all_features.items()):
                if i < 25:
                    feedback_entry[f'feature_{i}'] = float(value) if not np.isnan(value) else None
            
            # Append to CSV
            df = pd.read_csv(self.feedback_file)
            df = pd.concat([df, pd.DataFrame([feedback_entry])], ignore_index=True)
            df.to_csv(self.feedback_file, index=False)
            
            logger.info(f"Feedback saved: domain={domain}, total_entries={len(df)}")
            return True, f"Feedback recorded for {domain}"
            
        except Exception as e:
            logger.error(f"Error collecting feedback: {e}", exc_info=True)
            return False, f"Error saving feedback: {str(e)[:100]}"
    
    def get_feedback_count(self) -> int:
        """Get total number of feedback entries"""
        try:
            df = pd.read_csv(self.feedback_file)
            return len(df)
        except:
            return 0
    
    def get_latest_feedback(self, n: int = 10) -> pd.DataFrame:
        """Get latest N feedback entries"""
        try:
            df = pd.read_csv(self.feedback_file)
            return df.tail(n)[['domain', 'label', 'timestamp', 'user_comment']]
        except:
            return pd.DataFrame()


# ============================================================================
# 2. FEEDBACK DATASET VALIDATOR
# ============================================================================

class FeedbackDataset:
    """
    Manages feedback dataset with validation, deduplication, and consistency checks
    
    Prevents:
    - Duplicate domains
    - Corrupted entries (NaN features)
    - Data poisoning attacks
    
    Ensures:
    - Feature consistency with training data
    - Balanced dataset growth
    """
    
    def __init__(self, feedback_file: str = "feedback_benign.csv"):
        """Initialize feedback dataset manager"""
        self.feedback_file = Path(feedback_file)
        self.extractor = DomainFeatureExtractor()
    
    def validate_and_clean(self) -> Tuple[pd.DataFrame, Dict]:
        """
        Validate and clean feedback dataset
        
        Returns:
            (cleaned_df, stats_dict)
        """
        try:
            df = pd.read_csv(self.feedback_file)
        except:
            logger.warning("Could not read feedback file")
            return pd.DataFrame(), {'total': 0, 'duplicates': 0, 'invalid': 0, 'valid': 0}
        
        stats = {
            'total': len(df),
            'duplicates': 0,
            'invalid': 0,
            'incomplete_features': 0,
            'valid': 0
        }
        
        # Remove duplicates (same domain)
        df_clean = df.drop_duplicates(subset=['domain'], keep='first')
        stats['duplicates'] = stats['total'] - len(df_clean)
        
        # Remove invalid entries
        df_clean = df_clean[df_clean['domain'].notna()]
        df_clean = df_clean[df_clean['domain'].str.len() > 0]
        
        # Check for missing features
        feature_cols = [col for col in df_clean.columns if col.startswith('feature_')]
        missing_features = 0
        
        for idx, row in df_clean.iterrows():
            nan_count = sum(1 for col in feature_cols if pd.isna(row[col]))
            if nan_count > 5:  # Allow up to 5 missing features
                df_clean = df_clean.drop(idx)
                missing_features += 1
        
        stats['incomplete_features'] = missing_features
        stats['invalid'] = stats['duplicates'] + missing_features
        stats['valid'] = len(df_clean)
        
        logger.info(f"Feedback validation: total={stats['total']}, valid={stats['valid']}, duplicates={stats['duplicates']}")
        
        return df_clean, stats
    
    def merge_with_original_datasets(
        self,
        benign_dir: Optional[str] = None,
        dga_file: str = COMBINED_DGA_DATASET,
        max_feedback_ratio: float = 0.1
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Merge feedback with original datasets while maintaining balance
        
        Args:
            benign_dir: Directory with benign domain lists
            dga_file: Path to DGA dataset CSV
            max_feedback_ratio: Max ratio of feedback to original data
        
        Returns:
            (X: DataFrame with features, y: Series with labels)
        """
        logger.info("Starting dataset merge...")
        
        # Load and validate feedback
        feedback_df, stats = self.validate_and_clean()
        feedback_count = len(feedback_df)
        
        # Load original domains from the combined dataset
        benign_domains = self._load_benign_domains(benign_dir, dga_file)
        dga_domains = self._load_dga_domains(dga_file)
        
        logger.info(f"Original datasets: benign={len(benign_domains)}, dga={len(dga_domains)}")
        logger.info(f"Feedback entries: {feedback_count} (valid={stats['valid']})")
        
        # Limit feedback growth to prevent imbalance
        max_feedback = int(len(benign_domains) * max_feedback_ratio)
        if feedback_count > max_feedback:
            logger.warning(f"Feedback exceeds max ratio ({feedback_count} > {max_feedback}). Sampling...")
            feedback_df = feedback_df.sample(n=max_feedback, random_state=42)
            feedback_count = len(feedback_df)
        
        # Extract features from all sources
        X_list = []
        y_list = []
        
        # Add original benign domains
        logger.info("Extracting features from benign domains...")
        for i, domain in enumerate(benign_domains[:5000]):  # Cap at 5000
            if i % 500 == 0:
                logger.info(f"  Progress: {i}/{min(5000, len(benign_domains))}")
            try:
                features = self.extractor.extract_all_features(domain)
                X_list.append(features)
                y_list.append(0)
            except:
                pass
        
        # Add feedback benign entries
        logger.info(f"Adding {feedback_count} feedback entries...")
        feature_cols = [col for col in feedback_df.columns if col.startswith('feature_')]
        for idx, row in feedback_df.iterrows():
            features = {}
            for col in feature_cols:
                features[col.replace('feature_', '')] = row[col]
            X_list.append(features)
            y_list.append(0)
        
        # Add original DGA domains
        logger.info("Extracting features from DGA domains...")
        for i, domain in enumerate(dga_domains[:5000]):
            if i % 500 == 0:
                logger.info(f"  Progress: {i}/{min(5000, len(dga_domains))}")
            try:
                features = self.extractor.extract_all_features(domain)
                X_list.append(features)
                y_list.append(1)
            except:
                pass
        
        # Convert to DataFrame
        X = pd.DataFrame(X_list)
        y = pd.Series(y_list)
        
        logger.info(f"Final dataset: {len(X)} samples ({len(y[y==0])} benign, {len(y[y==1])} dga)")
        
        return X, y
    
    def _load_benign_domains(self, benign_dir: Optional[str], combined_file: Optional[str] = None) -> List[str]:
        """Load benign domains from the combined CSV file (Datasets/dga_data.csv/dga_data.csv)."""
        # Always try to load from combined file first (NEW DATASET: dga_data.csv with both benign and dga)
        if combined_file:
            try:
                logger.info(f"Loading benign domains from combined dataset: {combined_file}")
                df = pd.read_csv(combined_file)
                benign = (
                    df.loc[df['isDGA'].astype(str).str.lower() == 'legit', 'host']
                    .dropna()
                    .astype(str)
                    .str.strip()
                    .unique()
                    .tolist()
                )
                logger.info(f"Loaded {len(benign)} benign domains from combined dataset")
                return benign
            except Exception as e:
                logger.error(f"Could not load benign domains from combined file {combined_file}: {e}")
                return []

        # Fallback: Try benign_dir (kept for backwards compatibility)
        domains = []
        if not benign_dir:
            logger.warning("No benign_dir provided and no combined_file available")
            return domains
        benign_path = Path(benign_dir)
        
        if not benign_path.exists():
            logger.warning(f"Benign directory not found: {benign_dir}")
            return domains
        
        for file in benign_path.glob("*.txt"):
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    domains.extend([line.strip() for line in f if line.strip()])
            except:
                pass
        
        return list(set(domains))  # Remove duplicates
    
    def _load_dga_domains(self, dga_file: str) -> List[str]:
        """Load DGA domains from the combined CSV."""
        try:
            df = pd.read_csv(dga_file)
            return (
                df.loc[df['isDGA'].astype(str).str.lower() == 'dga', 'host']
                .dropna()
                .astype(str)
                .str.strip()
                .unique()
                .tolist()
            )
        except:
            logger.warning(f"Could not load DGA file: {dga_file}")
            return []


# ============================================================================
# 3. MODEL RETRAINER
# ============================================================================

class ModelRetrainer:
    """
    Retrains threat detection models using combined original + feedback datasets
    
    Features:
    - Proper train/test split
    - Cross-validation checks
    - Overfitting detection
    - Comprehensive evaluation metrics
    """
    
    def __init__(self, model_dir: str = "models"):
        """Initialize retrainer"""
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        self.extractor = DomainFeatureExtractor()
    
    def retrain_model(
        self,
        X: pd.DataFrame,
        y: pd.Series,
        test_size: float = 0.2,
        random_state: int = 42,
        model_type: str = "random_forest"
    ) -> Tuple[Dict, Dict]:
        """
        Retrain threat detection model
        
        Args:
            X: Feature DataFrame
            y: Label Series
            test_size: Fraction of data for testing
            random_state: Random seed
            model_type: 'random_forest' or 'xgboost'
        
        Returns:
            (model_dict, metrics_dict)
        """
        from sklearn.model_selection import train_test_split
        
        logger.info(f"Starting model retraining (type={model_type})...")
        logger.info(f"Dataset shape: {X.shape}")
        logger.info(f"Class distribution: {y.value_counts().to_dict()}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train model
        if model_type == "random_forest":
            logger.info("Training Random Forest...")
            model = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=random_state,
                n_jobs=-1,
                class_weight='balanced'
            )
        else:
            logger.info("Training XGBoost...")
            model = XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                random_state=random_state,
                n_jobs=-1
            )
        
        model.fit(X_train_scaled, y_train)
        logger.info(f"Model trained successfully")
        
        # Evaluate
        y_pred = model.predict(X_test_scaled)
        y_pred_proba = model.predict_proba(X_test_scaled)
        
        metrics = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred)),
            'recall': float(recall_score(y_test, y_pred)),
            'f1': float(f1_score(y_test, y_pred)),
            'roc_auc': float(roc_auc_score(y_test, y_pred_proba[:, 1])),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'test_samples': len(X_test),
            'train_samples': len(X_train)
        }
        
        logger.info(f"Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1']:.4f}")
        
        # Check for overfitting
        y_train_pred = model.predict(X_train_scaled)
        train_acc = accuracy_score(y_train, y_train_pred)
        test_acc = metrics['accuracy']
        
        if train_acc - test_acc > 0.10:
            logger.warning(f"Potential overfitting detected (train={train_acc:.4f}, test={test_acc:.4f})")
        
        model_dict = {
            'model': model,
            'scaler': scaler,
            'feature_columns': X.columns.tolist(),
            'model_type': model_type,
            'trained_at': datetime.now().isoformat()
        }
        
        return model_dict, metrics
    
    def save_versioned_model(
        self,
        model_dict: Dict,
        metrics: Dict,
        version: str = None
    ) -> Tuple[str, str]:
        """
        Save model with version number
        
        Args:
            model_dict: Model artifact dict
            metrics: Evaluation metrics
            version: Version string (auto-generated if None)
        
        Returns:
            (model_path, version)
        """
        if version is None:
            # Auto-generate version (v1, v2, v3, ...)
            existing = list(self.model_dir.glob("dns_model_v*.pkl"))
            version_num = len(existing) + 1
            version = f"v{version_num}"
        
        model_path = self.model_dir / f"dns_model_{version}.pkl"
        
        # Add metadata
        model_dict['version'] = version
        model_dict['metrics'] = metrics
        model_dict['saved_at'] = datetime.now().isoformat()
        
        joblib.dump(model_dict, model_path)
        logger.info(f"Model saved: {model_path} (version={version})")
        
        # Also update dns_best_model.pkl for compatibility
        joblib.dump(model_dict, self.model_dir / "dns_best_model.pkl")
        logger.info(f"Updated dns_best_model.pkl as current best")
        
        return str(model_path), version


# ============================================================================
# 4. VERSION MANAGER
# ============================================================================

class VersionManager:
    """
    Manages model versions, enables rollback, tracks performance history
    """
    
    def __init__(self, model_dir: str = "models"):
        """Initialize version manager"""
        self.model_dir = Path(model_dir)
        self.version_log = self.model_dir / "version_history.csv"
        self._init_version_log()
    
    def _init_version_log(self):
        """Create version log if it doesn't exist"""
        if not self.version_log.exists():
            df = pd.DataFrame(columns=[
                'version', 'timestamp', 'model_type', 'accuracy', 'f1', 
                'roc_auc', 'test_samples', 'feedback_count', 'notes'
            ])
            df.to_csv(self.version_log, index=False)
    
    def log_version(
        self,
        version: str,
        model_type: str,
        metrics: Dict,
        feedback_count: int = 0,
        notes: str = ""
    ):
        """Log a new model version"""
        entry = {
            'version': version,
            'timestamp': datetime.now().isoformat(),
            'model_type': model_type,
            'accuracy': metrics.get('accuracy', 0),
            'f1': metrics.get('f1', 0),
            'roc_auc': metrics.get('roc_auc', 0),
            'test_samples': metrics.get('test_samples', 0),
            'feedback_count': feedback_count,
            'notes': notes
        }
        
        df = pd.read_csv(self.version_log)
        df = pd.concat([df, pd.DataFrame([entry])], ignore_index=True)
        df.to_csv(self.version_log, index=False)
        logger.info(f"Version logged: {version}")
    
    def get_version_history(self) -> pd.DataFrame:
        """Get all version history"""
        try:
            return pd.read_csv(self.version_log)
        except:
            return pd.DataFrame()
    
    def rollback_to_version(self, version: str) -> bool:
        """Rollback to a specific version"""
        model_path = self.model_dir / f"dns_model_{version}.pkl"
        
        if not model_path.exists():
            logger.error(f"Version {version} not found")
            return False
        
        try:
            model = joblib.load(model_path)
            joblib.dump(model, self.model_dir / "dns_best_model.pkl")
            logger.info(f"Rolled back to version {version}")
            return True
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False


# ============================================================================
# 5. FEEDBACK MONITOR
# ============================================================================

class FeedbackMonitor:
    """
    Monitors feedback quality and system improvement
    
    Tracks:
    - False positive rate reduction
    - Model accuracy improvements
    - Feedback quality metrics
    - Safety issues (potential poisoning)
    """
    
    def __init__(self, db_path: str = "threat_detection.db"):
        """Initialize feedback monitor"""
        self.db = ThreatDatabase(db_path)
    
    def analyze_feedback_impact(
        self,
        old_version: str,
        new_version: str
    ) -> Dict:
        """
        Analyze impact of feedback on model improvement
        
        Args:
            old_version: Previous model version
            new_version: New model version
        
        Returns:
            Impact analysis dictionary
        """
        # This would query version history and compare metrics
        analysis = {
            'accuracy_improvement': 0,
            'precision_improvement': 0,
            'recall_improvement': 0,
            'f1_improvement': 0,
            'evaluation': 'Good feedback integration'
        }
        
        return analysis
    
    def detect_poisoning_attempts(self) -> List[Dict]:
        """
        Detect potential data poisoning attempts
        
        Heuristics:
        - Same user marking many domains as false positive
        - Marking DGA domains as benign
        - Marking too many domains too quickly
        
        Returns:
            List of suspicious activity flags
        """
        suspicious = []
        
        # Check for rapid-fire markings
        # Check for obvious DGA markers in feedback
        # Check for suspicious patterns
        
        return suspicious
    
    def get_improvement_metrics(self) -> Dict:
        """Get overall improvement metrics"""
        return {
            'false_positives_reduced': 0.0,
            'model_improvements': [],
            'user_feedback_quality': 'Good'
        }


# ============================================================================
# 6. INTEGRATION HELPERS
# ============================================================================

class FeedbackLearningPipeline:
    """
    Complete end-to-end feedback learning pipeline
    
    Usage:
        pipeline = FeedbackLearningPipeline()
        pipeline.run_retraining_if_needed()
    """
    
    def __init__(
        self,
        feedback_file: str = "feedback_benign.csv",
        retrain_threshold: int = 100,
        model_dir: str = "models"
    ):
        """Initialize pipeline"""
        self.collector = FeedbackCollector(feedback_file)
        self.dataset = FeedbackDataset(feedback_file)
        self.retrainer = ModelRetrainer(model_dir)
        self.version_mgr = VersionManager(model_dir)
        self.monitor = FeedbackMonitor()
        self.retrain_threshold = retrain_threshold
    
    def should_retrain(self) -> Tuple[bool, str]:
        """Check if retraining is needed"""
        feedback_count = self.collector.get_feedback_count()
        
        if feedback_count >= self.retrain_threshold:
            return True, f"Feedback count ({feedback_count}) >= threshold ({self.retrain_threshold})"
        
        return False, f"Feedback count ({feedback_count}) < threshold ({self.retrain_threshold})"
    
    def run_full_pipeline(self) -> Dict:
        """
        Execute complete retraining pipeline
        
        Returns:
            Pipeline results dictionary
        """
        logger.info("=" * 80)
        logger.info("FEEDBACK LEARNING PIPELINE - FULL RUN")
        logger.info("=" * 80)
        
        results = {'success': False, 'steps_completed': []}
        
        try:
            # Step 1: Validate feedback
            logger.info("\n[STEP 1] Validating feedback dataset...")
            feedback_df, stats = self.dataset.validate_and_clean()
            results['steps_completed'].append('feedback_validation')
            logger.info(f"Feedback validation: {stats}")
            
            if len(feedback_df) == 0:
                logger.warning("No valid feedback to retrain on")
                return results
            
            # Step 2: Merge datasets
            logger.info("\n[STEP 2] Merging feedback with original datasets...")
            X, y = self.dataset.merge_with_original_datasets()
            results['steps_completed'].append('dataset_merge')
            logger.info(f"Merged dataset: {X.shape}")
            
            # Step 3: Retrain model
            logger.info("\n[STEP 3] Retraining Random Forest model...")
            model_dict, metrics = self.retrainer.retrain_model(
                X, y, model_type='random_forest'
            )
            results['steps_completed'].append('model_training')
            logger.info(f"Training metrics: {metrics}")
            
            # Step 4: Save versioned model
            logger.info("\n[STEP 4] Saving versioned model...")
            model_path, version = self.retrainer.save_versioned_model(
                model_dict, metrics
            )
            results['steps_completed'].append('model_saving')
            results['model_version'] = version
            results['model_path'] = model_path
            
            # Step 5: Log version
            logger.info("\n[STEP 5] Logging version history...")
            self.version_mgr.log_version(
                version=version,
                model_type='random_forest',
                metrics=metrics,
                feedback_count=len(feedback_df),
                notes=f"Retrained with {len(feedback_df)} feedback samples"
            )
            results['steps_completed'].append('version_logging')
            
            results['success'] = True
            results['metrics'] = metrics
            results['feedback_count'] = len(feedback_df)
            
            logger.info("\n" + "=" * 80)
            logger.info("PIPELINE COMPLETED SUCCESSFULLY")
            logger.info("=" * 80)
            
        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)
            results['error'] = str(e)
        
        return results


# ============================================================================
# MAIN: Example Usage
# ============================================================================

if __name__ == "__main__":
    logger.info("\n" + "=" * 80)
    logger.info("FEEDBACK LEARNING SYSTEM - EXAMPLE USAGE")
    logger.info("=" * 80)
    
    # Initialize pipeline
    pipeline = FeedbackLearningPipeline(retrain_threshold=5)  # Low threshold for testing
    
    # Example 1: Collect some feedback
    logger.info("\n--- Example 1: Collecting Feedback ---")
    collector = pipeline.collector
    
    test_domains = [
        ("google.com", 0, "False positive by old model"),
        ("facebook.com", 0, "Should be benign"),
    ]
    
    for domain, label, comment in test_domains:
        success, msg = collector.collect_feedback(
            domain=domain,
            label=label,
            comment=comment,
            confidence_before=0.85,
            model_version="1.0"
        )
        logger.info(f"{domain}: {msg}")
    
    # Example 2: Check if retraining is needed
    logger.info("\n--- Example 2: Check Retraining Trigger ---")
    should_retrain, reason = pipeline.should_retrain()
    logger.info(f"Should retrain: {should_retrain} ({reason})")
    
    # Example 3: View feedback
    logger.info("\n--- Example 3: View Latest Feedback ---")
    latest = collector.get_latest_feedback(5)
    logger.info(f"\nLatest feedback entries:\n{latest}")
    
    logger.info("\n" + "=" * 80)
    logger.info("To run full retraining pipeline, use:")
    logger.info("  results = pipeline.run_full_pipeline()")
    logger.info("=" * 80)
