# ============================================================
#  ThreatPulse AI - ml_engine.py
#  Hybrid 4-Layer AI Threat Detection Engine
#
#  Layer 1: Rule Engine       - Instant pattern matching
#  Layer 2: Isolation Forest  - Anomaly detection (unsupervised)
#  Layer 3: Random Forest     - Threat classification (supervised)
#  Layer 4: CNN-LSTM Hybrid   - Deep sequence analysis (NEW)
#
#  Final score = weighted vote from all 4 layers
#  CNN extracts spatial features per packet
#  LSTM detects attack sequences across time
# ============================================================

import os
import threading
import logging
import numpy as np
from collections import defaultdict, deque
from datetime import datetime

logger = logging.getLogger("sentinel.ml")

# ── Model paths ───────────────────────────────────────────
MODEL_DIR      = os.path.join(os.path.dirname(__file__), "models")
IFOREST_PATH   = os.path.join(MODEL_DIR, "isolation_forest.joblib")
RF_PATH        = os.path.join(MODEL_DIR, "random_forest.joblib")
CNN_LSTM_PATH  = os.path.join(MODEL_DIR, "cnn_lstm_model.keras")
SCALER_PATH    = os.path.join(MODEL_DIR, "cnn_lstm_scaler.joblib")
os.makedirs(MODEL_DIR, exist_ok=True)

# ── Feature encoding ──────────────────────────────────────
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3, "OTHER": 4}
FLAG_MAP = {
    "NONE": 0, "S": 1, "SA": 2, "A": 3, "FA": 4,
    "PA": 5, "RA": 6, "R": 7, "F": 8,
}

# Sequence length for LSTM (how many past packets to consider)
SEQ_LEN = 20


def encode_packet(record: dict) -> np.ndarray:
    """
    Turn one packet dict into an 11-feature numeric vector.
    Features:
      0  protocol_id       - TCP=0 UDP=1 ICMP=2 HTTP=3 OTHER=4
      1  src_port          - 0-65535
      2  dst_port          - 0-65535
      3  packet_size       - bytes
      4  ttl               - 0-255
      5  tcp_flag_id       - encoded flag string
      6  is_http           - 1 if HTTP else 0
      7  is_well_known_port - 1 if dst_port < 1024
      8  is_high_port      - 1 if src_port > 49151
      9  port_ratio        - dst/src ratio (capped at 1000)
     10  size_bucket       - 0=tiny 1=small 2=medium 3=large
    """
    proto    = PROTOCOL_MAP.get(record.get("protocol", "OTHER"), 4)
    src_port = record.get("src_port") or 0
    dst_port = record.get("dst_port") or 0
    size     = record.get("packet_size") or 0
    ttl      = record.get("ttl") or 0
    flags    = record.get("tcp_flags") or "NONE"
    flag_id  = FLAG_MAP.get(flags, 0)

    is_http       = 1 if record.get("protocol") == "HTTP" else 0
    is_well_known = 1 if 0 < dst_port < 1024 else 0
    is_high_src   = 1 if src_port > 49151 else 0
    port_ratio    = min((dst_port / src_port) if src_port > 0 else 0, 1000)
    size_bucket   = 0 if size < 64 else (1 if size < 512 else (2 if size < 1400 else 3))

    return np.array([
        proto, src_port, dst_port, size, ttl,
        flag_id, is_http, is_well_known, is_high_src,
        port_ratio, size_bucket
    ], dtype=np.float32)


# ── Layer 1: Rule Engine ──────────────────────────────────
class RuleEngine:
    """Zero-latency checks based on known attack patterns."""

    _ip_packet_times = defaultdict(lambda: deque(maxlen=200))
    _ip_syn_counts   = defaultdict(int)
    _lock            = threading.Lock()

    SUSPICIOUS_PORTS = {
        22: "SSH Brute Force", 23: "Telnet", 3389: "RDP",
        1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
        6379: "Redis", 27017: "MongoDB", 4444: "Metasploit",
        1337: "Hacker Port", 31337: "Elite/Backdoor",
    }

    PRIVATE_PREFIXES = (
        "192.168.", "10.", "172.16.", "172.17.", "172.18.",
        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
        "172.29.", "172.30.", "172.31.", "127.", "::1", ""
    )

    def is_private(self, ip: str) -> bool:
        if not ip:
            return True
        return any(ip.startswith(p) for p in self.PRIVATE_PREFIXES)

    def check(self, record: dict):
        src_ip   = record.get("src_ip", "")
        dst_ip   = record.get("dst_ip", "")
        dst_port = record.get("dst_port") or 0
        protocol = record.get("protocol", "")
        flags    = record.get("tcp_flags", "")
        size     = record.get("packet_size") or 0
        now      = datetime.utcnow().timestamp()
        src_priv = self.is_private(src_ip)

        with self._lock:
            times = self._ip_packet_times[src_ip]
            times.append(now)

            if flags == "S" and protocol == "TCP":
                self._ip_syn_counts[src_ip] = self._ip_syn_counts.get(src_ip, 0) + 1

            recent_5s = sum(1 for t in times if now - t <= 5)
            syn_count = self._ip_syn_counts.get(src_ip, 0)

            # SYN Flood - external
            if not src_priv and syn_count > 50:
                self._ip_syn_counts[src_ip] = 0
                return True, self._threat("SYN Flood", "CRITICAL", src_ip, dst_ip, dst_port, protocol,
                    f"SYN flood from external IP {src_ip} ({syn_count} SYNs)")

            # SYN Flood - internal
            if src_priv and syn_count > 200:
                self._ip_syn_counts[src_ip] = 0
                return True, self._threat("SYN Flood", "MEDIUM", src_ip, dst_ip, dst_port, protocol,
                    f"Internal SYN flood from {src_ip} ({syn_count} SYNs)")

            # Port Scan - external
            if not src_priv and recent_5s > 20:
                return True, self._threat("Port Scan", "HIGH", src_ip, dst_ip, dst_port, protocol,
                    f"Port scan from external {src_ip} ({recent_5s} pkts/5s)")

            # Port Scan - internal
            if src_priv and recent_5s > 20:
                return True, self._threat("Port Scan", "LOW", src_ip, dst_ip, dst_port, protocol,
                    f"Internal port scan from {src_ip} ({recent_5s} pkts/5s)")

            # DDoS
            if not src_priv and recent_5s > 100:
                return True, self._threat("DDoS", "CRITICAL", src_ip, dst_ip, dst_port, protocol,
                    f"DDoS traffic from {src_ip} ({recent_5s} pkts/5s)")

            # Suspicious port
            if dst_port in self.SUSPICIOUS_PORTS and not src_priv:
                svc = self.SUSPICIOUS_PORTS[dst_port]
                return True, self._threat("Suspicious Port", "HIGH", src_ip, dst_ip, dst_port, protocol,
                    f"Connection to suspicious port {dst_port} ({svc}) from {src_ip}")

            # Oversized ICMP
            if protocol == "ICMP" and size > 1000:
                return True, self._threat("ICMP Flood", "MEDIUM", src_ip, dst_ip, dst_port, protocol,
                    f"Oversized ICMP packet from {src_ip} ({size} bytes)")

        return False, None

    def _threat(self, ttype, severity, src_ip, dst_ip, dst_port, protocol, desc):
        return {
            "threat_type": ttype, "severity": severity,
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": None, "dst_port": dst_port,
            "protocol": protocol, "description": desc,
            "timestamp": datetime.utcnow().isoformat(), "resolved": 0,
        }


# ── Layer 2: Isolation Forest (Anomaly Detection) ─────────
class AnomalyDetector:
    """Unsupervised anomaly detection - learns normal traffic."""

    def __init__(self, threshold: float = 0.65, train_size: int = 500):
        self.threshold  = threshold
        self.train_size = train_size
        self.model      = None
        self._trained   = False
        self._buffer    = []
        self._lock      = threading.Lock()
        self._try_load()

    def _try_load(self):
        if os.path.exists(IFOREST_PATH):
            try:
                import joblib
                self.model   = joblib.load(IFOREST_PATH)
                self._trained = True
                logger.info("Loaded existing Isolation Forest model.")
            except Exception as e:
                logger.warning(f"Could not load IForest model: {e}")

    def score(self, features: np.ndarray) -> float:
        with self._lock:
            self._buffer.append(features)
            if not self._trained:
                if len(self._buffer) >= self.train_size:
                    self._train()
                return 0.0
            try:
                raw = self.model.score_samples(features.reshape(1, -1))[0]
                # Convert: more negative = more anomalous -> scale to 0-1
                return float(np.clip(1.0 - (raw + 0.5), 0.0, 1.0))
            except Exception:
                return 0.0

    def _train(self):
        try:
            from sklearn.ensemble import IsolationForest
            import joblib
            X = np.array(self._buffer[-self.train_size:])
            self.model = IsolationForest(
                n_estimators=100, contamination=0.1,
                random_state=42, n_jobs=-1
            )
            self.model.fit(X)
            joblib.dump(self.model, IFOREST_PATH)
            self._trained = True
            logger.info(f"Isolation Forest trained on {len(X)} samples.")
        except Exception as e:
            logger.error(f"IForest training failed: {e}")


# ── Layer 3: Random Forest (Threat Classifier) ────────────
class ThreatClassifier:
    """Supervised classifier trained on labelled threat/normal data."""

    THREAT_TYPES = [
        "Normal", "Port Scan", "SYN Flood",
        "Brute Force", "DDoS", "Malware C2",
    ]

    def __init__(self, train_size: int = 500):
        self.model      = None
        self._trained   = False
        self._buffer_X  = []
        self._buffer_y  = []
        self.train_size = train_size
        self._lock      = threading.Lock()
        self._try_load()

    def _try_load(self):
        if os.path.exists(RF_PATH):
            try:
                import joblib
                self.model   = joblib.load(RF_PATH)
                self._trained = True
                logger.info("Loaded existing Random Forest model.")
            except Exception as e:
                logger.warning(f"Could not load RF model: {e}")

    def classify(self, features: np.ndarray, is_threat: bool) -> str:
        with self._lock:
            self._buffer_X.append(features)
            self._buffer_y.append(1 if is_threat else 0)
            if not self._trained:
                if len(self._buffer_X) >= self.train_size:
                    self._train()
                return "Unknown" if is_threat else "Normal"
            try:
                pred = self.model.predict(features.reshape(1, -1))[0]
                if pred == 0:
                    return "Normal"
                idx = int(pred) % (len(self.THREAT_TYPES) - 1) + 1
                return self.THREAT_TYPES[idx]
            except Exception:
                return "Unknown"

    def _train(self):
        try:
            from sklearn.ensemble import RandomForestClassifier
            import joblib
            X = np.array(self._buffer_X[-self.train_size:])
            y = np.array(self._buffer_y[-self.train_size:])
            if len(np.unique(y)) < 2:
                return
            self.model = RandomForestClassifier(
                n_estimators=100, max_depth=10,
                random_state=42, n_jobs=-1, class_weight="balanced"
            )
            self.model.fit(X, y)
            joblib.dump(self.model, RF_PATH)
            self._trained = True
            logger.info(f"Random Forest trained on {len(X)} samples.")
        except Exception as e:
            logger.error(f"RF training failed: {e}")


# ── Layer 4: CNN-LSTM Hybrid ──────────────────────────────
class CNNLSTMDetector:
    """
    Deep learning hybrid model combining:
    - 1D CNN: extracts spatial feature patterns from each packet
    - LSTM:   detects sequential attack patterns across time

    Architecture:
      Input (SEQ_LEN x 11 features)
        |
      Conv1D(64 filters, kernel=3) -> ReLU -> MaxPool
        |
      Conv1D(128 filters, kernel=3) -> ReLU -> MaxPool
        |
      LSTM(64 units, return_sequences=False)
        |
      Dense(32) -> Dropout(0.3)
        |
      Dense(1) -> Sigmoid (threat probability 0-1)
    """

    def __init__(self, seq_len: int = SEQ_LEN, train_size: int = 1000):
        self.seq_len    = seq_len
        self.train_size = train_size
        self.model      = None
        self.scaler     = None
        self._trained   = False
        self._lock      = threading.Lock()

        # Sliding window buffer per source IP
        # {src_ip: deque of feature vectors}
        self._ip_sequences = defaultdict(lambda: deque(maxlen=seq_len))

        # Training buffer: (sequence, label)
        self._train_X = []
        self._train_y = []

        self._try_load()

    def _try_load(self):
        """Load pre-trained model if exists."""
        try:
            if os.path.exists(CNN_LSTM_PATH) and os.path.exists(SCALER_PATH):
                import joblib
                # Try loading keras model
                try:
                    import tensorflow as tf
                    self.model   = tf.keras.models.load_model(CNN_LSTM_PATH)
                    self.scaler  = joblib.load(SCALER_PATH)
                    self._trained = True
                    logger.info("Loaded existing CNN-LSTM model.")
                except Exception as e:
                    logger.warning(f"Could not load CNN-LSTM: {e}")
        except Exception:
            pass

    def _build_model(self):
        """Build the CNN-LSTM architecture."""
        try:
            import tensorflow as tf
            from tensorflow.keras.models import Sequential
            from tensorflow.keras.layers import (
                Conv1D, MaxPooling1D, LSTM, Dense,
                Dropout, BatchNormalization, Input
            )

            model = Sequential([
                Input(shape=(self.seq_len, 11)),

                # CNN Block 1 - local feature extraction
                Conv1D(64, kernel_size=3, activation='relu', padding='same'),
                BatchNormalization(),
                MaxPooling1D(pool_size=2, padding='same'),

                # CNN Block 2 - higher level patterns
                Conv1D(128, kernel_size=3, activation='relu', padding='same'),
                BatchNormalization(),
                MaxPooling1D(pool_size=2, padding='same'),

                # LSTM - temporal sequence analysis
                LSTM(64, return_sequences=False, dropout=0.2),

                # Classifier head
                Dense(32, activation='relu'),
                Dropout(0.3),
                Dense(1, activation='sigmoid'),
            ])

            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            return model
        except ImportError:
            logger.warning("TensorFlow not installed. CNN-LSTM layer disabled.")
            return None

    def update_sequence(self, src_ip: str, features: np.ndarray):
        """Add packet features to IP's sliding window."""
        with self._lock:
            self._ip_sequences[src_ip].append(features.copy())

    def predict(self, src_ip: str) -> float:
        """
        Predict threat probability for an IP's recent packet sequence.
        Returns 0.0-1.0 threat score. 0.0 if not enough data or untrained.
        """
        with self._lock:
            seq = list(self._ip_sequences.get(src_ip, []))

        if len(seq) < 3:
            return 0.0

        if not self._trained or self.model is None:
            return 0.0

        try:
            # Pad sequence to seq_len
            padded = np.zeros((self.seq_len, 11), dtype=np.float32)
            seq_arr = np.array(seq[-self.seq_len:], dtype=np.float32)
            padded[-len(seq_arr):] = seq_arr

            # Scale features
            flat    = padded.reshape(-1, 11)
            scaled  = self.scaler.transform(flat)
            padded  = scaled.reshape(1, self.seq_len, 11)

            # Predict
            prob = float(self.model.predict(padded, verbose=0)[0][0])
            return prob
        except Exception as e:
            logger.debug(f"CNN-LSTM predict error: {e}")
            return 0.0

    def add_training_sample(self, src_ip: str, is_threat: bool):
        """Store current sequence as training sample."""
        with self._lock:
            seq = list(self._ip_sequences.get(src_ip, []))
            if len(seq) < 5:
                return

            padded = np.zeros((self.seq_len, 11), dtype=np.float32)
            seq_arr = np.array(seq[-self.seq_len:], dtype=np.float32)
            padded[-len(seq_arr):] = seq_arr

            self._train_X.append(padded)
            self._train_y.append(1 if is_threat else 0)

            # Train when enough samples collected
            if len(self._train_X) >= self.train_size:
                self._train_async()

    def _train_async(self):
        """Train CNN-LSTM in background thread so capture isn't blocked."""
        t = threading.Thread(target=self._train, daemon=True)
        t.start()

    def _train(self):
        """Train the CNN-LSTM model on collected sequences."""
        try:
            import joblib
            from sklearn.preprocessing import StandardScaler

            with self._lock:
                X = np.array(self._train_X[-self.train_size:], dtype=np.float32)
                y = np.array(self._train_y[-self.train_size:], dtype=np.float32)
                # Clear buffer after taking samples
                self._train_X = self._train_X[-200:]
                self._train_y = self._train_y[-200:]

            if len(np.unique(y)) < 2:
                logger.info("CNN-LSTM: waiting for both classes to train...")
                return

            # Scale features across all sequences
            flat   = X.reshape(-1, 11)
            scaler = StandardScaler()
            scaled = scaler.fit_transform(flat)
            X_scaled = scaled.reshape(X.shape)

            # Build model
            model = self._build_model()
            if model is None:
                return

            # Train with early stopping
            import tensorflow as tf
            callback = tf.keras.callbacks.EarlyStopping(
                monitor='val_loss', patience=3, restore_best_weights=True
            )

            model.fit(
                X_scaled, y,
                epochs=20,
                batch_size=32,
                validation_split=0.2,
                callbacks=[callback],
                verbose=0,
            )

            # Save model and scaler
            model.save(CNN_LSTM_PATH)
            joblib.dump(scaler, SCALER_PATH)

            with self._lock:
                self.model   = model
                self.scaler  = scaler
                self._trained = True

            logger.info(f"CNN-LSTM trained on {len(X)} sequences. Model saved.")

        except ImportError:
            logger.warning("TensorFlow not available. CNN-LSTM training skipped.")
        except Exception as e:
            logger.error(f"CNN-LSTM training failed: {e}")


# ── Main Engine: 4-Layer Hybrid ───────────────────────────
class SentinelMLEngine:
    """
    Hybrid 4-layer threat detection engine.

    Voting system:
      Layer 1 (Rules)    - weight 0.40  (highest - instant, certain)
      Layer 2 (IForest)  - weight 0.20
      Layer 3 (RF)       - weight 0.20
      Layer 4 (CNN-LSTM) - weight 0.20  (grows in importance as it trains)

    Final threat score = weighted sum of all layer scores.
    """

    # Layer weights for final score
    WEIGHTS = {
        "rules":    0.40,
        "iforest":  0.20,
        "rf":       0.20,
        "cnn_lstm": 0.20,
    }

    def __init__(self):
        threshold  = float(os.environ.get("ANOMALY_THRESHOLD", "0.65"))
        train_size = int(os.environ.get("ML_TRAIN_SIZE", "500"))

        self.rules    = RuleEngine()
        self.anomaly  = AnomalyDetector(threshold=threshold, train_size=train_size)
        self.classify = ThreatClassifier(train_size=train_size)
        self.cnn_lstm = CNNLSTMDetector(seq_len=SEQ_LEN, train_size=train_size * 2)

        logger.info("SentinelMLEngine initialised (4-layer hybrid: Rules + IForest + RF + CNN-LSTM).")

    def analyse(self, record: dict) -> dict:
        """
        Full 4-layer hybrid analysis of one packet.
        Returns: {is_threat, threat_score, threat_detail, layer_scores}
        """
        src_ip = record.get("src_ip", "unknown")

        # ── Layer 1: Rule Engine ──────────────────────────
        is_rule_threat, threat_detail = self.rules.check(record)
        rule_score = 0.95 if is_rule_threat else 0.0

        # ── Feature extraction ────────────────────────────
        try:
            features = encode_packet(record)
        except Exception:
            features = np.zeros(11, dtype=np.float32)

        # ── Layer 2: Isolation Forest ─────────────────────
        try:
            anomaly_score = self.anomaly.score(features)
        except Exception:
            anomaly_score = 0.0

        is_anomaly = anomaly_score >= self.anomaly.threshold

        # ── Layer 3: Random Forest ────────────────────────
        try:
            threat_type = self.classify.classify(features, is_rule_threat or is_anomaly)
            rf_score    = 0.85 if (threat_type not in ("Normal", "Unknown") and
                                   (is_rule_threat or is_anomaly)) else 0.0
        except Exception:
            threat_type = "Unknown"
            rf_score    = 0.0

        # ── Layer 4: CNN-LSTM ─────────────────────────────
        # Update sequence for this IP
        self.cnn_lstm.update_sequence(src_ip, features)

        try:
            cnn_lstm_score = self.cnn_lstm.predict(src_ip)
        except Exception:
            cnn_lstm_score = 0.0

        # Feed training signals to CNN-LSTM
        if is_rule_threat or is_anomaly:
            self.cnn_lstm.add_training_sample(src_ip, True)
        elif anomaly_score < 0.3:
            self.cnn_lstm.add_training_sample(src_ip, False)

        # ── Hybrid Voting ─────────────────────────────────
        final_score = (
            self.WEIGHTS["rules"]    * rule_score      +
            self.WEIGHTS["iforest"]  * anomaly_score   +
            self.WEIGHTS["rf"]       * rf_score        +
            self.WEIGHTS["cnn_lstm"] * cnn_lstm_score
        )
        final_score = round(float(np.clip(final_score, 0.0, 1.0)), 4)

        # Determine final threat decision
        # Rule engine always wins if triggered
        is_threat = (
            is_rule_threat or
            is_anomaly or
            cnn_lstm_score >= 0.75  # CNN-LSTM high confidence
        )

        # Build threat detail if none from rules
        if is_threat and not threat_detail:
            # Determine which layer detected it
            if cnn_lstm_score >= 0.75 and not is_anomaly:
                detection_method = f"CNN-LSTM sequence analysis (score {cnn_lstm_score:.2f})"
                description = (
                    f"Deep learning sequence anomaly detected from {src_ip}. "
                    f"CNN-LSTM identified suspicious packet sequence pattern "
                    f"(score {cnn_lstm_score:.2f})"
                )
            else:
                detection_method = f"Anomaly detection (score {anomaly_score:.2f})"
                description = (
                    f"AI anomaly detected from {src_ip} "
                    f"(anomaly={anomaly_score:.2f}, cnn_lstm={cnn_lstm_score:.2f})"
                )

            threat_detail = {
                "threat_type":  threat_type if threat_type not in ("Normal", "Unknown") else "Anomaly",
                "severity":     self._severity(final_score),
                "src_ip":       src_ip,
                "dst_ip":       record.get("dst_ip", ""),
                "src_port":     record.get("src_port"),
                "dst_port":     record.get("dst_port"),
                "protocol":     record.get("protocol", ""),
                "description":  description,
                "timestamp":    datetime.utcnow().isoformat(),
                "resolved":     0,
            }
        elif threat_detail:
            # Update severity using hybrid score for rule threats
            threat_detail["severity"] = self._severity(final_score)

        # If no actual threat, clear detail
        if not is_threat:
            threat_detail = None

        return {
            "is_threat":    is_threat,
            "threat_score": final_score,
            "threat_detail": threat_detail,
            # Layer scores for debugging/logging
            "layer_scores": {
                "rules":    round(rule_score, 3),
                "iforest":  round(anomaly_score, 3),
                "rf":       round(rf_score, 3),
                "cnn_lstm": round(cnn_lstm_score, 3),
                "final":    final_score,
            }
        }

    def _severity(self, score: float) -> str:
        if score >= 0.85:
            return "CRITICAL"
        if score >= 0.70:
            return "HIGH"
        if score >= 0.50:
            return "MEDIUM"
        return "LOW"

    def get_model_status(self) -> dict:
        """Return status of all 4 layers - useful for the AI log page."""
        return {
            "rule_engine":    {"status": "active",  "type": "rule-based"},
            "isolation_forest": {
                "status":  "trained" if self.anomaly._trained else "training",
                "type":    "unsupervised",
                "samples": len(self.anomaly._buffer),
            },
            "random_forest": {
                "status":  "trained" if self.classify._trained else "training",
                "type":    "supervised",
                "samples": len(self.classify._buffer_X),
            },
            "cnn_lstm": {
                "status":  "trained" if self.cnn_lstm._trained else "training",
                "type":    "deep-learning",
                "samples": len(self.cnn_lstm._train_X),
                "architecture": "Conv1D(64) -> Conv1D(128) -> LSTM(64) -> Dense(1)",
            },
        }
