"""
ML-Based Anomaly Detection Engine
Uses Isolation Forest for unsupervised anomaly detection and
Random Forest for traffic classification.
"""

import numpy as np
import random
from datetime import datetime


class MLEngine:
    """Machine learning engine for network traffic anomaly detection."""

    FEATURE_NAMES = [
        "protocol_encoded",
        "mode_encoded",
        "payload_size",
        "ttl",
        "encryption_key_size",
        "crypto_secure",
        "sequence_number",
        "spi_numeric",
        "is_ike",
        "pfs_enabled",
    ]

    ANOMALY_LABELS = {
        0: "normal",
        1: "replay_attack",
        2: "flood_attack",
        3: "spi_spoofing",
        4: "downgrade_attempt",
        5: "sequence_anomaly",
        6: "unusual_payload",
        7: "rogue_endpoint",
        8: "timing_anomaly",
    }

    def __init__(self):
        self.isolation_forest = None
        self.random_forest = None
        self.is_trained = False
        self._train_on_synthetic()

    def _train_on_synthetic(self):
        """Train models on synthetic data for immediate use."""
        try:
            from sklearn.ensemble import IsolationForest, RandomForestClassifier
            from sklearn.preprocessing import StandardScaler

            # Generate training data
            normal_data, normal_labels = self._generate_training_data(n_normal=2000, n_anomaly=0)
            anomaly_data, anomaly_labels = self._generate_training_data(n_normal=0, n_anomaly=400)

            # Combine for classifier
            all_data = np.vstack([normal_data, anomaly_data])
            all_labels = np.concatenate([normal_labels, anomaly_labels])

            # Train Isolation Forest (unsupervised anomaly detector)
            self.isolation_forest = IsolationForest(
                n_estimators=100,
                contamination=0.15,
                random_state=42,
            )
            self.isolation_forest.fit(normal_data)

            # Train Random Forest Classifier (supervised classification)
            self.random_forest = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
            )
            self.random_forest.fit(all_data, all_labels)

            self.scaler = StandardScaler()
            self.scaler.fit(all_data)

            self.is_trained = True
        except ImportError:
            # sklearn not available — use rule-based fallback
            self.is_trained = False

    def _generate_training_data(self, n_normal=1000, n_anomaly=200):
        """Generate synthetic training data."""
        data = []
        labels = []

        # Normal traffic
        for _ in range(n_normal):
            data.append([
                random.choice([0, 1, 2, 3]),       # protocol
                random.choice([0, 1]),              # mode
                random.randint(64, 1400),           # payload_size
                random.choice([64, 128, 255]),      # ttl
                random.choice([128, 256]),           # key_size
                1,                                   # crypto_secure
                random.randint(1, 100000),           # sequence_number
                random.randint(256, 2**31),          # spi_numeric
                random.choice([0, 0, 0, 1]),         # is_ike
                random.choice([0, 1, 1, 1]),         # pfs_enabled
            ])
            labels.append(0)

        # Anomalous traffic
        for _ in range(n_anomaly):
            anomaly_type = random.randint(1, 8)

            if anomaly_type == 1:  # replay
                row = [0, 0, random.randint(64, 1400), 64, 256, 1,
                       random.choice([1, 2, 3]), random.randint(256, 2**31), 0, 1]
            elif anomaly_type == 2:  # flood
                row = [2, 0, random.randint(40, 80), 64, 256, 1,
                       random.randint(1, 100), random.randint(256, 2**31), 1, 1]
            elif anomaly_type == 3:  # spi_spoofing
                row = [0, 0, random.randint(64, 1400), 64, 256, 1,
                       random.randint(1, 100000), random.randint(1, 255), 0, 1]
            elif anomaly_type == 4:  # downgrade
                row = [0, 0, random.randint(64, 1400), 64, random.choice([0, 56, 168]), 0,
                       random.randint(1, 100000), random.randint(256, 2**31), 0, 0]
            elif anomaly_type == 5:  # sequence
                row = [0, 0, random.randint(64, 1400), 64, 256, 1,
                       random.randint(900000, 999999), random.randint(256, 2**31), 0, 1]
            elif anomaly_type == 6:  # unusual payload
                row = [0, 0, random.randint(9000, 65535), 64, 256, 1,
                       random.randint(1, 100000), random.randint(256, 2**31), 0, 1]
            elif anomaly_type == 7:  # rogue
                row = [0, 0, random.randint(64, 1400), random.choice([1, 2, 3]), 256, 1,
                       random.randint(1, 100000), random.randint(256, 2**31), 0, 1]
            else:  # timing
                row = [0, 0, random.randint(64, 1400), 64, 256, 1,
                       random.randint(1, 100000), random.randint(256, 2**31), 0, 1]

            data.append(row)
            labels.append(anomaly_type)

        return np.array(data, dtype=float), np.array(labels)

    def analyze_packets(self, packets):
        """Run anomaly detection on a list of packets."""
        if not packets:
            return {"anomalies": [], "summary": {}, "model_info": {}}

        features_list = []
        for pkt in packets:
            features = pkt.get("features", {})
            row = [features.get(f, 0) for f in self.FEATURE_NAMES]
            features_list.append(row)

        X = np.array(features_list, dtype=float)

        if self.is_trained:
            return self._ml_analysis(X, packets)
        else:
            return self._rule_based_analysis(packets)

    def _ml_analysis(self, X, packets):
        """ML-based analysis using trained models."""
        # Isolation Forest: anomaly scores
        anomaly_scores = self.isolation_forest.decision_function(X)
        anomaly_predictions = self.isolation_forest.predict(X)  # 1 = normal, -1 = anomaly

        # Random Forest: classification
        class_predictions = self.random_forest.predict(X)
        class_probabilities = self.random_forest.predict_proba(X)

        # Feature importances
        importances = self.random_forest.feature_importances_

        anomalies = []
        for i, pkt in enumerate(packets):
            is_anomaly_if = anomaly_predictions[i] == -1
            is_anomaly_rf = class_predictions[i] != 0
            is_anomaly = is_anomaly_if or is_anomaly_rf

            # Normalize anomaly score to 0-1 range
            raw_score = anomaly_scores[i]
            normalized_score = max(0, min(1, 0.5 - raw_score))

            result = {
                "packet_id": pkt.get("id", i),
                "timestamp": pkt.get("timestamp", ""),
                "src_ip": pkt.get("src_ip", ""),
                "dst_ip": pkt.get("dst_ip", ""),
                "protocol": pkt.get("protocol", ""),
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": round(float(normalized_score), 4),
                "anomaly_type": self.ANOMALY_LABELS.get(int(class_predictions[i]), "unknown"),
                "confidence": round(float(max(class_probabilities[i])) * 100, 2),
                "severity": self._score_to_severity(normalized_score),
            }

            if is_anomaly:
                anomalies.append(result)

        # Summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        type_counts = {}
        for a in anomalies:
            severity_counts[a["severity"]] = severity_counts.get(a["severity"], 0) + 1
            type_counts[a["anomaly_type"]] = type_counts.get(a["anomaly_type"], 0) + 1

        return {
            "total_analyzed": len(packets),
            "total_anomalies": len(anomalies),
            "anomaly_rate": round(len(anomalies) / max(len(packets), 1) * 100, 2),
            "anomalies": anomalies,
            "all_results": [
                {
                    "packet_id": pkt.get("id", i),
                    "anomaly_score": round(float(max(0, min(1, 0.5 - anomaly_scores[i]))), 4),
                    "is_anomaly": bool(anomaly_predictions[i] == -1 or class_predictions[i] != 0),
                    "timestamp": pkt.get("timestamp", ""),
                }
                for i, pkt in enumerate(packets)
            ],
            "severity_distribution": severity_counts,
            "anomaly_type_distribution": type_counts,
            "feature_importances": {
                self.FEATURE_NAMES[i]: round(float(importances[i]), 4)
                for i in range(len(self.FEATURE_NAMES))
            },
            "model_info": {
                "isolation_forest": {"n_estimators": 100, "contamination": 0.15},
                "random_forest": {"n_estimators": 100, "max_depth": 10},
                "training_samples": 2400,
                "is_trained": True,
            },
        }

    def _rule_based_analysis(self, packets):
        """Fallback rule-based analysis when sklearn is not available."""
        anomalies = []

        for i, pkt in enumerate(packets):
            features = pkt.get("features", {})
            score = 0.0
            reasons = []

            # Rule: weak crypto
            if features.get("crypto_secure", 1) == 0:
                score += 0.3
                reasons.append("Weak encryption detected")

            # Rule: suspicious sequence numbers
            seq = features.get("sequence_number", 0)
            if seq < 5 or seq > 900000:
                score += 0.25
                reasons.append("Suspicious sequence number")

            # Rule: unusual payload size
            size = features.get("payload_size", 0)
            if size > 9000 or size < 40:
                score += 0.2
                reasons.append("Unusual payload size")

            # Rule: small SPI (potential spoofing)
            spi = features.get("spi_numeric", 0)
            if spi < 256:
                score += 0.25
                reasons.append("Suspicious SPI value")

            # Rule: no PFS
            if features.get("pfs_enabled", 1) == 0:
                score += 0.1
                reasons.append("PFS disabled")

            is_anomaly = score >= 0.3 or pkt.get("is_anomaly", False)

            if is_anomaly:
                anomalies.append({
                    "packet_id": pkt.get("id", i),
                    "timestamp": pkt.get("timestamp", ""),
                    "src_ip": pkt.get("src_ip", ""),
                    "dst_ip": pkt.get("dst_ip", ""),
                    "protocol": pkt.get("protocol", ""),
                    "is_anomaly": True,
                    "anomaly_score": round(min(score, 1.0), 4),
                    "anomaly_type": pkt.get("anomaly_type", "unknown"),
                    "confidence": round(min(score * 100, 99), 2),
                    "severity": self._score_to_severity(score),
                    "reasons": reasons,
                })

        return {
            "total_analyzed": len(packets),
            "total_anomalies": len(anomalies),
            "anomaly_rate": round(len(anomalies) / max(len(packets), 1) * 100, 2),
            "anomalies": anomalies,
            "model_info": {"type": "rule_based", "is_trained": False},
        }

    def _score_to_severity(self, score):
        if score >= 0.8: return "critical"
        if score >= 0.6: return "high"
        if score >= 0.4: return "medium"
        if score >= 0.2: return "low"
        return "info"
