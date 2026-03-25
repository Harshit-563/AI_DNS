import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
    roc_curve,
)
from xgboost import XGBClassifier

from scripts.Analysis import build_default_analyzer
from data_engg import extractor
from scripts.data_set import DatasetBuilder


class DNSThreatDetectionModel:
    """Train and evaluate DNS threat detection models."""

    def __init__(self, X_train, X_test, y_train, y_test, scaler=None):
        self.X_train = X_train
        self.X_test = X_test
        self.y_train = y_train
        self.y_test = y_test
        self.scaler = scaler
        self.models = {}
        self.results = {}
        self.model_dir = Path("models")

    def train_random_forest(self):
        """Train Random Forest model."""
        print("\n" + "=" * 60)
        print("TRAINING RANDOM FOREST")
        print("=" * 60)

        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=1,
            class_weight="balanced",
        )

        model.fit(self.X_train, self.y_train)
        self.models["Random Forest"] = model

        print("[OK] Random Forest trained")
        model_path = self.save_model("Random Forest", "dns_rf_model.pkl")
        print(f"[OK] Random Forest saved to {model_path}")
        return model

    def train_xgboost(self):
        """Train XGBoost model."""
        print("\n" + "=" * 60)
        print("TRAINING XGBOOST")
        print("=" * 60)

        positive_count = (self.y_train == 1).sum()
        negative_count = (self.y_train == 0).sum()
        scale_pos_weight = negative_count / max(positive_count, 1)

        model = XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            n_jobs=1,
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
        )

        model.fit(self.X_train, self.y_train)
        self.models["XGBoost"] = model

        print("[OK] XGBoost trained")
        model_path = self.save_model("XGBoost", "dns_xgb_model.pkl")
        print(f"[OK] XGBoost saved to {model_path}")
        return model

    def train_gradient_boosting(self):
        """Train Gradient Boosting model."""
        print("\n" + "=" * 60)
        print("TRAINING GRADIENT BOOSTING")
        print("=" * 60)

        model = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42,
        )

        model.fit(self.X_train, self.y_train)
        self.models["Gradient Boosting"] = model

        print("[OK] Gradient Boosting trained")
        return model

    def train_logistic_regression(self):
        """Train Logistic Regression baseline."""
        print("\n" + "=" * 60)
        print("TRAINING LOGISTIC REGRESSION (BASELINE)")
        print("=" * 60)

        model = LogisticRegression(
            max_iter=1000,
            random_state=42,
            n_jobs=1,
            class_weight="balanced",
        )

        model.fit(self.X_train, self.y_train)
        self.models["Logistic Regression"] = model

        print("[OK] Logistic Regression trained")
        return model

    def evaluate_model(self, model_name):
        """Evaluate a model."""
        model = self.models[model_name]

        y_pred = model.predict(self.X_test)
        y_pred_proba = model.predict_proba(self.X_test)[:, 1]

        results = {
            "accuracy": accuracy_score(self.y_test, y_pred),
            "f1": f1_score(self.y_test, y_pred),
            "auc_roc": roc_auc_score(self.y_test, y_pred_proba),
            "y_pred": y_pred,
            "y_pred_proba": y_pred_proba,
        }

        self.results[model_name] = results

        print(f"\n{model_name} Performance:")
        print(f"  Accuracy: {results['accuracy']:.4f}")
        print(f"  F1-Score: {results['f1']:.4f}")
        print(f"  AUC-ROC: {results['auc_roc']:.4f}")
        print("\nClassification Report:")
        print(classification_report(self.y_test, y_pred, target_names=["Benign", "Malicious"]))

        return results

    def evaluate_all(self):
        """Evaluate all trained models."""
        print("\n" + "=" * 60)
        print("MODEL EVALUATION")
        print("=" * 60)

        for model_name in self.models:
            self.evaluate_model(model_name)

    def plot_roc_curves(self):
        """Plot ROC curves for all models."""
        plt.figure(figsize=(10, 6))

        for model_name, results in self.results.items():
            fpr, tpr, _ = roc_curve(self.y_test, results["y_pred_proba"])
            plt.plot(fpr, tpr, label=f"{model_name} (AUC={results['auc_roc']:.3f})")

        plt.plot([0, 1], [0, 1], "k--", label="Random")
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title("ROC Curves - DNS Threat Detection")
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig("roc_curves.png", dpi=300, bbox_inches="tight")
        print("\n[OK] ROC curves saved to roc_curves.png")
        plt.close()

    def plot_confusion_matrix(self, model_name):
        """Plot confusion matrix."""
        results = self.results[model_name]
        cm = confusion_matrix(self.y_test, results["y_pred"])

        plt.figure(figsize=(8, 6))
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=["Benign", "Malicious"],
            yticklabels=["Benign", "Malicious"],
        )
        plt.title(f"Confusion Matrix - {model_name}")
        plt.ylabel("True Label")
        plt.xlabel("Predicted Label")
        plt.tight_layout()
        plt.savefig(f"confusion_matrix_{model_name.replace(' ', '_')}.png", dpi=300)
        print("[OK] Confusion matrix saved")
        plt.close()

    def get_feature_importance(self, model_name):
        """Get feature importance for tree-based models."""
        model = self.models[model_name]

        if hasattr(model, "feature_importances_"):
            return pd.DataFrame(
                {
                    "feature": self.X_train.columns,
                    "importance": model.feature_importances_,
                }
            ).sort_values("importance", ascending=False)

        print(f"{model_name} doesn't support feature importance")
        return None

    def plot_feature_importance(self, model_name, top_n=20):
        """Plot feature importance."""
        importance_df = self.get_feature_importance(model_name)

        if importance_df is not None:
            plt.figure(figsize=(10, 6))
            importance_df.head(top_n).plot(x="feature", y="importance", kind="barh")
            plt.xlabel("Importance")
            plt.title(f"Top {top_n} Feature Importance - {model_name}")
            plt.tight_layout()
            plt.savefig(f"feature_importance_{model_name.replace(' ', '_')}.png", dpi=300)
            print("[OK] Feature importance saved")
            plt.close()

    def save_model(self, model_name, filename):
        """Persist a trained model to disk and return its path."""
        model = self.models[model_name]
        self.model_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.model_dir / filename
        model_bundle = {
            "model": model,
            "model_name": model_name,
            "feature_columns": list(self.X_train.columns),
            "scaler": self.scaler,
        }
        joblib.dump(model_bundle, output_path)
        return output_path


def build_training_data(max_samples_per_class=50000, test_size=0.2):
    analyzer = build_default_analyzer()
    dataset_builder = DatasetBuilder(
        analyzer.benign_domains,
        analyzer.malicious_domains,
        extractor,
    )
    dataset_builder.build_dataset(max_samples_per_class=max_samples_per_class)
    dataset_builder.handle_class_imbalance(method="undersample")
    X_train, X_test, y_train, y_test = dataset_builder.prepare_features(test_size=test_size)
    return X_train, X_test, y_train, y_test, dataset_builder.scaler


if __name__ == "__main__":
    X_train, X_test, y_train, y_test, scaler = build_training_data()

    trainer = DNSThreatDetectionModel(X_train, X_test, y_train, y_test, scaler=scaler)
    trainer.train_random_forest()
    trainer.train_xgboost()
    trainer.train_gradient_boosting()
    trainer.train_logistic_regression()

    trainer.evaluate_all()
    trainer.plot_roc_curves()
    trainer.plot_confusion_matrix("XGBoost")
    trainer.plot_feature_importance("XGBoost", top_n=20)

    best_model_name = max(trainer.results, key=lambda name: trainer.results[name]["f1"])
    print(f"\n{'=' * 60}")
    print(f"BEST MODEL: {best_model_name}")
    print(f"{'=' * 60}")
    best_model_path = trainer.save_model(best_model_name, "dns_best_model.pkl")
    print(f"[OK] Best model saved to {best_model_path}")
