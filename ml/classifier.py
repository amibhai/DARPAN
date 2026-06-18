"""
DARPAN Threat Actor Classifier
Random Forest with SHAP explainability for session threat classification.
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from feature_engineering import NUMERIC_FEATURE_COLS

log = logging.getLogger("darpan.classifier")

THREAT_CLASSES = [
    "SCRIPT_KIDDIE",
    "AUTOMATED_SCANNER",
    "ADVANCED_HUMAN",
    "APT_CANDIDATE",
    "WORM_BOT",
]

CLASS_DESCRIPTIONS = {
    "SCRIPT_KIDDIE":      "Low-skill manual attacker using known exploits/tools",
    "AUTOMATED_SCANNER":  "Automated scanning tool (Shodan, Masscan, ZMap-based)",
    "ADVANCED_HUMAN":     "Skilled human operator with targeted intent",
    "APT_CANDIDATE":      "Advanced persistent threat — sophisticated TTPs, evasion",
    "WORM_BOT":           "Self-propagating worm or botnet agent",
}

FEATURE_EXPLANATIONS = {
    "iat_mean":                "Inter-arrival time between commands (mean seconds)",
    "iat_std":                 "Command timing variance — low = robotic, high = human",
    "commands_per_minute":     "Command execution rate",
    "time_to_first_command":   "Latency between auth and first command",
    "command_count":           "Total commands in session",
    "unique_command_ratio":    "Proportion of unique commands — low = scripted loop",
    "recon_command_score":     "Count of reconnaissance commands (ls, cat, id, etc.)",
    "lateral_movement_score":  "Count of lateral movement commands (ssh, nc, wget)",
    "persistence_command_score": "Count of persistence commands (crontab, chmod +x)",
    "payload_entropy":         "Shannon entropy of command strings — high = obfuscated",
    "avg_command_length":      "Average command string length",
    "base64_usage_flag":       "Base64 encoding detected in commands",
    "contains_ip_address_flag": "Hardcoded IP addresses in commands",
    "contains_url_flag":       "URLs present in commands",
    "auth_success":            "Whether attacker successfully authenticated",
    "syntax_error_rate":       "Fraction of commands with 'not found' — high = scripted",
}


class DARPANClassifier:
    def __init__(
        self,
        n_estimators: int = 200,
        max_depth: int = 15,
        random_state: int = 42,
        model_dir: str = "/opt/darpan/ml",
    ):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        self._clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1,
            oob_score=True,
        )
        self._label_enc = LabelEncoder()
        self._explainer: shap.TreeExplainer | None = None
        self._feature_cols: list[str] = []
        self.trained = False

    def _prepare_X(self, df: pd.DataFrame) -> pd.DataFrame:
        cols = [c for c in self._feature_cols if c in df.columns]
        X = df[cols].copy()
        X = X.fillna(0).replace([np.inf, -np.inf], 0)
        return X

    def train(self, X: pd.DataFrame, y: pd.Series) -> dict[str, Any]:
        self._feature_cols = list(X.columns)
        y_enc = self._label_enc.fit_transform(y)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
        )

        self._clf.fit(X_train, y_train)
        self.trained = True

        # Build SHAP explainer once after training
        self._explainer = shap.TreeExplainer(self._clf)

        y_pred = self._clf.predict(X_test)
        report = classification_report(
            y_test, y_pred,
            target_names=self._label_enc.classes_,
            output_dict=True,
        )
        log.info(f"OOB score: {self._clf.oob_score_:.4f}")
        log.info("\n" + classification_report(y_test, y_pred,
                                              target_names=self._label_enc.classes_))

        self._save_confusion_matrix(y_test, y_pred)
        return {"oob_score": self._clf.oob_score_, "classification_report": report}

    def predict(self, X: pd.DataFrame) -> list[str]:
        X_prep = self._prepare_X(X)
        y_enc = self._clf.predict(X_prep)
        return list(self._label_enc.inverse_transform(y_enc))

    def predict_proba(self, X: pd.DataFrame) -> pd.DataFrame:
        X_prep = self._prepare_X(X)
        proba = self._clf.predict_proba(X_prep)
        return pd.DataFrame(proba, columns=self._label_enc.classes_, index=X.index)

    def save_model(self, path: str | Path | None = None) -> Path:
        if path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = self.model_dir / f"darpan_rf_{ts}.joblib"
        path = Path(path)
        payload = {
            "clf": self._clf,
            "label_enc": self._label_enc,
            "feature_cols": self._feature_cols,
        }
        joblib.dump(payload, path)
        log.info(f"Model saved to {path}")

        # Keep a symlink to latest
        latest = self.model_dir / "darpan_rf_latest.joblib"
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        latest.symlink_to(path.name)
        return path

    def load_model(self, path: str | Path | None = None) -> None:
        if path is None:
            path = self.model_dir / "darpan_rf_latest.joblib"
        payload = joblib.load(str(path))
        self._clf = payload["clf"]
        self._label_enc = payload["label_enc"]
        self._feature_cols = payload["feature_cols"]
        self._explainer = shap.TreeExplainer(self._clf)
        self.trained = True
        log.info(f"Model loaded from {path}")

    def generate_shap_summary_plot(
        self, X: pd.DataFrame, output_path: str | Path
    ) -> None:
        if self._explainer is None:
            raise RuntimeError("Model not trained or loaded")
        X_prep = self._prepare_X(X)
        shap_values = self._explainer.shap_values(X_prep)

        plt.figure(figsize=(12, 8))
        shap.summary_plot(
            shap_values,
            X_prep,
            class_names=self._label_enc.classes_,
            show=False,
            max_display=20,
        )
        plt.title("DARPAN — SHAP Feature Importance by Threat Class")
        plt.tight_layout()
        plt.savefig(str(output_path), dpi=150, bbox_inches="tight")
        plt.close()
        log.info(f"SHAP summary plot saved to {output_path}")

    def explain_session(
        self, session_features: pd.DataFrame, top_n: int = 5
    ) -> dict[str, Any]:
        if self._explainer is None:
            raise RuntimeError("Model not trained or loaded")

        X_prep = self._prepare_X(session_features)
        predicted_class = self.predict(session_features)[0]
        proba = self.predict_proba(session_features).iloc[0]
        confidence = float(proba.max())

        class_idx = list(self._label_enc.classes_).index(predicted_class)
        shap_values = self._explainer.shap_values(X_prep)

        if isinstance(shap_values, list):
            sv = shap_values[class_idx][0]
        else:
            sv = shap_values[0]

        # Rank features by absolute SHAP value
        feat_impact = sorted(
            zip(self._feature_cols, sv),
            key=lambda x: abs(x[1]),
            reverse=True,
        )[:top_n]

        reasons = []
        for feat, impact in feat_impact:
            val = float(X_prep.iloc[0].get(feat, 0))
            direction = "increases" if impact > 0 else "decreases"
            description = FEATURE_EXPLANATIONS.get(feat, feat)
            reasons.append({
                "feature": feat,
                "value": round(val, 4),
                "shap_impact": round(float(impact), 4),
                "direction": direction,
                "description": description,
            })

        explanation_text = self._build_explanation_text(
            predicted_class, confidence, reasons
        )

        return {
            "threat_class": predicted_class,
            "confidence": round(confidence, 4),
            "class_probabilities": proba.round(4).to_dict(),
            "class_description": CLASS_DESCRIPTIONS.get(predicted_class, ""),
            "top_features": reasons,
            "explanation": explanation_text,
        }

    def _build_explanation_text(
        self, threat_class: str, confidence: float, reasons: list[dict]
    ) -> str:
        lines = [
            f"This session was classified as {threat_class} "
            f"(confidence: {confidence:.1%}) because:"
        ]
        for i, r in enumerate(reasons, 1):
            val = r["value"]
            feat = r["feature"]
            desc = r["description"]
            if feat == "iat_mean":
                detail = f"{val:.2f}s avg — {'robotic pace' if val < 1 else 'human-like pace'}"
            elif feat == "payload_entropy":
                detail = f"{val:.2f} — {'high, suggests obfuscation' if val > 4 else 'normal'}"
            elif feat == "commands_per_minute":
                detail = f"{val:.1f} cmd/min — {'automated' if val > 60 else 'manual'}"
            else:
                detail = str(val)
            lines.append(f"  {i}. {desc}: {detail}")
        return "\n".join(lines)

    def _save_confusion_matrix(
        self, y_true: np.ndarray, y_pred: np.ndarray
    ) -> None:
        cm = confusion_matrix(y_true, y_pred)
        disp = ConfusionMatrixDisplay(
            confusion_matrix=cm,
            display_labels=self._label_enc.classes_,
        )
        fig, ax = plt.subplots(figsize=(10, 8))
        disp.plot(ax=ax, colorbar=True, cmap="Blues")
        ax.set_title("DARPAN Classifier — Confusion Matrix")
        plt.tight_layout()
        out = self.model_dir / "confusion_matrix.png"
        plt.savefig(str(out), dpi=150, bbox_inches="tight")
        plt.close()
        log.info(f"Confusion matrix saved to {out}")


def generate_synthetic_training_data(n_samples: int = 2000) -> tuple[pd.DataFrame, pd.Series]:
    """Generate synthetic labeled training data for bootstrapping the classifier."""
    rng = np.random.default_rng(42)
    rows = []
    labels = []

    profiles = {
        "SCRIPT_KIDDIE": {
            "iat_mean": (5, 15), "commands_per_minute": (2, 8),
            "command_count": (3, 15), "recon_command_score": (1, 5),
            "lateral_movement_score": (0, 2), "persistence_command_score": (0, 1),
            "payload_entropy": (2, 3.5), "base64_usage_flag": 0.05,
            "unique_command_ratio": (0.7, 1.0), "auth_success": 0.4,
        },
        "AUTOMATED_SCANNER": {
            "iat_mean": (0.05, 0.5), "commands_per_minute": (50, 200),
            "command_count": (1, 5), "recon_command_score": (0, 2),
            "lateral_movement_score": (0, 1), "persistence_command_score": (0, 0),
            "payload_entropy": (1.5, 2.5), "base64_usage_flag": 0.01,
            "unique_command_ratio": (0.9, 1.0), "auth_success": 0.1,
        },
        "ADVANCED_HUMAN": {
            "iat_mean": (2, 20), "commands_per_minute": (3, 20),
            "command_count": (15, 60), "recon_command_score": (5, 15),
            "lateral_movement_score": (2, 8), "persistence_command_score": (1, 5),
            "payload_entropy": (3, 4.5), "base64_usage_flag": 0.3,
            "unique_command_ratio": (0.5, 0.9), "auth_success": 0.7,
        },
        "APT_CANDIDATE": {
            "iat_mean": (1, 8), "commands_per_minute": (5, 30),
            "command_count": (20, 100), "recon_command_score": (8, 20),
            "lateral_movement_score": (5, 15), "persistence_command_score": (3, 10),
            "payload_entropy": (4.0, 5.5), "base64_usage_flag": 0.7,
            "unique_command_ratio": (0.3, 0.7), "auth_success": 0.8,
        },
        "WORM_BOT": {
            "iat_mean": (0.1, 1.5), "commands_per_minute": (20, 120),
            "command_count": (5, 25), "recon_command_score": (1, 6),
            "lateral_movement_score": (3, 10), "persistence_command_score": (2, 8),
            "payload_entropy": (2.5, 4.0), "base64_usage_flag": 0.5,
            "unique_command_ratio": (0.2, 0.6), "auth_success": 0.6,
        },
    }

    for label, profile in profiles.items():
        n = n_samples // len(profiles)
        for _ in range(n):
            iat_mean = rng.uniform(*profile["iat_mean"])
            cpm = rng.uniform(*profile["commands_per_minute"])
            cmd_count = int(rng.uniform(*profile["command_count"]))
            row = {
                "iat_mean": iat_mean,
                "iat_std": iat_mean * rng.uniform(0.1, 0.8),
                "iat_min": iat_mean * rng.uniform(0.1, 0.5),
                "iat_max": iat_mean * rng.uniform(1.5, 4.0),
                "commands_per_minute": cpm,
                "time_to_first_command": rng.uniform(0.5, 30),
                "session_duration": cmd_count / (cpm / 60),
                "command_count": cmd_count,
                "unique_command_ratio": rng.uniform(*profile["unique_command_ratio"]),
                "syntax_error_rate": rng.uniform(0, 0.3),
                "recon_command_score": int(rng.uniform(*profile["recon_command_score"])),
                "lateral_movement_score": int(rng.uniform(*profile["lateral_movement_score"])),
                "persistence_command_score": int(rng.uniform(*profile["persistence_command_score"])),
                "payload_entropy": rng.uniform(*profile["payload_entropy"]),
                "avg_command_length": rng.uniform(8, 60),
                "base64_usage_flag": int(rng.random() < profile["base64_usage_flag"]),
                "contains_ip_address_flag": int(rng.random() < 0.3),
                "contains_url_flag": int(rng.random() < 0.2),
                "auth_success": int(rng.random() < profile["auth_success"]),
                "dst_port": rng.choice([22, 23]),
            }
            rows.append(row)
            labels.append(label)

    df = pd.DataFrame(rows)
    return df, pd.Series(labels)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    log.info("Generating synthetic training data...")
    X, y = generate_synthetic_training_data(2000)

    clf = DARPANClassifier(model_dir="/opt/darpan/ml")
    log.info("Training classifier...")
    metrics = clf.train(X, y)
    log.info(f"OOB score: {metrics['oob_score']:.4f}")

    model_path = clf.save_model()
    log.info(f"Model saved: {model_path}")

    clf.generate_shap_summary_plot(X.head(500), "/opt/darpan/ml/shap_summary.png")
    log.info("SHAP plot saved")

    sample = X.head(1)
    explanation = clf.explain_session(sample)
    print("\nSample Explanation:")
    print(explanation["explanation"])
