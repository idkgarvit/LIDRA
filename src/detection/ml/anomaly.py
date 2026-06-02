"""
LIDRA v3 Statistical ML Anomaly Detection

Lightweight statistical anomaly detection using:
- Z-score analysis for numeric metrics
- Baseline learning from historical data  
- No heavy ML - pure statistics

Why not deep learning?
- Explainable (analysts understand why it flagged)
- Lightweight (no GPU needed)
- Fast (simple calculations)
- Works offline
"""

import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import statistics
import threading

logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""
    is_anomaly: bool
    severity: str  # low, medium, high, critical
    z_score: float
    explanation: str
    metric_name: str
    value: float
    baseline_mean: float
    baseline_stdev: float


@dataclass
class Baseline:
    """Statistical baseline for a metric."""
    entity: str
    metric: str
    mean: float
    stdev: float
    min_val: float
    max_val: float
    p50: float
    p95: float
    sample_count: int
    last_updated: datetime
    
    def to_dict(self) -> Dict:
        return {
            'entity': self.entity,
            'metric': self.metric,
            'mean': self.mean,
            'stdev': self.stdev,
            'min': self.min_val,
            'max': self.max_val,
            'p50': self.p50,
            'p95': self.p95,
            'samples': self.sample_count,
            'updated': self.last_updated.isoformat()
        }


class AnomalyDetector:
    """
    Statistical anomaly detection for security events.
    
    Tracks:
    - Per-user behavior (login frequency, commands, time patterns)
    - Per-host behavior (network connections, process count)
    - Per-service behavior (request rates, errors)
    """
    
    # Thresholds
    Z_SCORE_THRESHOLD_HIGH = 3.0
    Z_SCORE_THRESHOLD_MEDIUM = 2.5
    Z_SCORE_THRESHOLD_LOW = 2.0
    
    # Learning parameters
    MIN_SAMPLES_FOR_BASELINE = 10
    BASELINE_WINDOW_HOURS = 24
    BASELINE_DECAY_DAYS = 7
    
    def __init__(self):
        self.baselines: Dict[str, Baseline] = {}
        self.raw_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.detection_count = 0
        self.anomaly_count = 0
        
        self._lock = threading.Lock()
        self._learning_enabled = True
    
    def learn_baseline(self, entity: str, metric: str, values: List[float]):
        """
        Learn normal behavior for an entity/metric.
        Called periodically to build baselines.
        """
        if len(values) < self.MIN_SAMPLES_FOR_BASELINE:
            return None
        
        key = f"{entity}:{metric}"
        
        # Calculate statistics
        mean = statistics.mean(values)
        stdev = statistics.stdev(values) if len(values) > 1 else 1.0
        
        baseline = Baseline(
            entity=entity,
            metric=metric,
            mean=mean,
            stdev=stdev,
            min_val=min(values),
            max_val=max(values),
            p50=statistics.median(values),
            p95=self._percentile(values, 95),
            sample_count=len(values),
            last_updated=datetime.now()
        )
        
        with self._lock:
            self.baselines[key] = baseline
        
        logger.debug(f"Learned baseline for {key}: mean={mean:.2f}, stdev={stdev:.2f}")
        return baseline
    
    def _percentile(self, data: List[float], p: int) -> float:
        """Calculate percentile."""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        idx = int(len(sorted_data) * p / 100)
        return sorted_data[min(idx, len(sorted_data) - 1)]
    
    def detect(self, entity: str, metric: str, value: float) -> Optional[AnomalyResult]:
        """
        Detect if a value is anomalous compared to baseline.
        
        Returns AnomalyResult if anomalous, None if normal.
        """
        key = f"{entity}:{metric}"
        
        with self._lock:
            baseline = self.baselines.get(key)
        
        if not baseline:
            # No baseline yet - store for learning later
            self._store_raw(entity, metric, value)
            return None
        
        # Calculate z-score
        if baseline.stdev == 0:
            z_score = 0.0
        else:
            z_score = abs(value - baseline.mean) / baseline.stdev
        
        # Determine if anomalous and severity
        is_anomaly = z_score > self.Z_SCORE_THRESHOLD_LOW
        
        if not is_anomaly:
            return None
        
        if z_score > self.Z_SCORE_THRESHOLD_HIGH:
            severity = 'critical'
        elif z_score > self.Z_SCORE_THRESHOLD_MEDIUM:
            severity = 'high'
        elif z_score > self.Z_SCORE_THRESHOLD_LOW:
            severity = 'medium'
        else:
            severity = 'low'
        
        self.anomaly_count += 1
        
        # Generate explanation
        direction = "higher" if value > baseline.mean else "lower"
        explanation = (
            f"Value {value:.1f} is {z_score:.1f} standard deviations {direction} "
            f"than baseline (mean: {baseline.mean:.1f}, stdev: {baseline.stdev:.1f})"
        )
        
        return AnomalyResult(
            is_anomaly=True,
            severity=severity,
            z_score=z_score,
            explanation=explanation,
            metric_name=metric,
            value=value,
            baseline_mean=baseline.mean,
            baseline_stdev=baseline.stdev
        )
    
    def _store_raw(self, entity: str, metric: str, value: float):
        """Store raw value for future baseline learning."""
        key = f"{entity}:{metric}"
        self.raw_data[key].append({
            'value': value,
            'timestamp': datetime.now()
        })
    
    def get_baseline(self, entity: str, metric: str) -> Optional[Baseline]:
        """Get baseline for entity/metric."""
        key = f"{entity}:{metric}"
        return self.baselines.get(key)
    
    def get_metrics(self) -> Dict:
        """Get detection metrics."""
        return {
            'baselines_count': len(self.baselines),
            'raw_data_entries': sum(len(v) for v in self.raw_data.values()),
            'detections': self.detection_count,
            'anomalies': self.anomaly_count
        }


class SecurityAnomalyDetector:
    """
    High-level security-focused anomaly detection.
    Uses AnomalyDetector for specific security metrics.
    """
    
    def __init__(self):
        self.detector = AnomalyDetector()
        self._setup_scheduled_baseline_learning()
    
    def _setup_scheduled_baseline_learning(self):
        """Setup periodic baseline learning."""
        # In production, this would be a scheduled task
        pass
    
    def check_login_frequency(self, user: str, count: int) -> Optional[AnomalyResult]:
        """Check if user login frequency is anomalous."""
        return self.detector.detect(user, 'login_count', float(count))
    
    def check_connection_rate(self, host: str, rate: float) -> Optional[AnomalyResult]:
        """Check if connection rate is anomalous."""
        return self.detector.detect(host, 'connection_rate', rate)
    
    def check_process_count(self, host: str, count: int) -> Optional[AnomalyResult]:
        """Check if process count is anomalous."""
        return self.detector.detect(host, 'process_count', float(count))
    
    def check_data_transfer(self, user: str, bytes_sent: int) -> Optional[AnomalyResult]:
        """Check if data transfer volume is anomalous."""
        return self.detector.detect(user, 'data_transfer', float(bytes_sent))
    
    def check_command_frequency(self, user: str, count: int) -> Optional[AnomalyResult]:
        """Check if user command frequency is anomalous."""
        return self.detector.detect(user, 'command_count', float(count))
    
    def check_time_anomaly(self, user: str, hour: int) -> Optional[AnomalyResult]:
        """Check if activity at unusual time."""
        # Convert to sine/cosine for cyclic analysis
        hour_sin = 24 * 2 * 3.14159 * hour / 24
        return self.detector.detect(user, 'hour_of_day', hour_sin)
    
    def learn_from_history(self, historical_data: List[Dict]):
        """
        Learn baselines from historical data.
        
        Expected format:
        [
            {'entity': 'user1', 'metric': 'login_count', 'value': 5, 'timestamp': ...},
            ...
        ]
        """
        # Group by entity/metric
        grouped = defaultdict(list)
        
        for entry in historical_data:
            entity = entry.get('entity', '')
            metric = entry.get('metric', '')
            value = entry.get('value', 0)
            
            if entity and metric:
                grouped[f"{entity}:{metric}"].append(value)
        
        # Learn each baseline
        for key, values in grouped.items():
            entity, metric = key.split(':', 1)
            self.detector.learn_baseline(entity, metric, values)
        
        logger.info(f"Learned {len(grouped)} baselines from history")


def create_anomaly_detector() -> SecurityAnomalyDetector:
    """Factory function."""
    return SecurityAnomalyDetector()