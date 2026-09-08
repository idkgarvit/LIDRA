import logging
import os
import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import statistics

logger = logging.getLogger(__name__)

_ONNX_AVAILABLE = False
_ONNX_SESSION = None
_AUTOENCODER_SESSION = None

try:
    import onnxruntime
    _ONNX_AVAILABLE = True
    logger.info("[ML] onnxruntime available for ML inference")
except ImportError:
    logger.info("[ML] onnxruntime not installed; using statistical fallback")


_MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")


def _load_onnx_models():
    global _ONNX_SESSION, _AUTOENCODER_SESSION
    prefilter_path = os.path.join(_MODEL_DIR, "prefilter.onnx")
    autoencoder_path = os.path.join(_MODEL_DIR, "autoencoder.onnx")
    if not _ONNX_AVAILABLE:
        return
    try:
        if os.path.isfile(prefilter_path):
            _ONNX_SESSION = onnxruntime.InferenceSession(prefilter_path)
            logger.info(f"[ML] Loaded prefilter model from {prefilter_path}")
        if os.path.isfile(autoencoder_path):
            _AUTOENCODER_SESSION = onnxruntime.InferenceSession(autoencoder_path)
            logger.info(f"[ML] Loaded autoencoder model from {autoencoder_path}")
    except Exception as e:
        logger.warning(f"[ML] Failed to load ONNX models: {e}")


_load_onnx_models()


def _run_onnx_inference(features: List[float]) -> Optional[Dict]:
    if not _ONNX_SESSION:
        return None
    try:
        import numpy as np
        input_name = _ONNX_SESSION.get_inputs()[0].name
        arr = np.array([features], dtype=np.float32)
        outputs = _ONNX_SESSION.run(None, {input_name: arr})
        confidence = float(outputs[0][0][1]) if outputs[0].shape[1] > 1 else float(outputs[0][0][0])
        return {"confidence": confidence, "anomaly": confidence > 0.5}
    except Exception as e:
        logger.warning(f"[ML] ONNX inference failed: {e}")
        return None


def _run_autoencoder_inference(features: List[float]) -> Optional[float]:
    if not _AUTOENCODER_SESSION:
        return None
    try:
        import numpy as np
        input_name = _AUTOENCODER_SESSION.get_inputs()[0].name
        arr = np.array([features], dtype=np.float32)
        outputs = _AUTOENCODER_SESSION.run(None, {input_name: arr})
        recon_error = float(np.mean((arr - outputs[0]) ** 2))
        return recon_error
    except Exception as e:
        logger.warning(f"[ML] Autoencoder inference failed: {e}")
        return None


@dataclass
class AnomalyResult:
    is_anomaly: bool
    severity: str
    z_score: float
    explanation: str
    metric_name: str
    value: float
    baseline_mean: float
    baseline_stdev: float
    ml_confidence: Optional[float] = None
    recon_error: Optional[float] = None


@dataclass
class Baseline:
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
    Z_SCORE_THRESHOLD_HIGH = 3.0
    Z_SCORE_THRESHOLD_MEDIUM = 2.5
    Z_SCORE_THRESHOLD_LOW = 2.0

    MIN_SAMPLES_FOR_BASELINE = 10

    def __init__(self):
        self.baselines: Dict[str, Baseline] = {}
        self.raw_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.detection_count = 0
        self.anomaly_count = 0
        self._lock = threading.Lock()
        self._learning_enabled = True

    def learn_baseline(self, entity: str, metric: str, values: List[float]):
        if len(values) < self.MIN_SAMPLES_FOR_BASELINE:
            return None

        key = f"{entity}:{metric}"

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
        if not data:
            return 0.0
        sorted_data = sorted(data)
        idx = int(len(sorted_data) * p / 100)
        return sorted_data[min(idx, len(sorted_data) - 1)]

    def _zscore_analysis(self, baseline: Baseline, value: float) -> Tuple[bool, str, float]:
        if baseline.stdev == 0:
            z_score = 0.0
        else:
            z_score = abs(value - baseline.mean) / baseline.stdev

        if z_score > self.Z_SCORE_THRESHOLD_HIGH:
            return True, 'critical', z_score
        if z_score > self.Z_SCORE_THRESHOLD_MEDIUM:
            return True, 'high', z_score
        if z_score > self.Z_SCORE_THRESHOLD_LOW:
            return True, 'medium', z_score
        return False, 'low', z_score

    def detect(self, entity: str, metric: str, value: float) -> Optional[AnomalyResult]:
        key = f"{entity}:{metric}"

        with self._lock:
            baseline = self.baselines.get(key)

        if not baseline:
            self._store_raw(entity, metric, value)
            return None

        is_anomaly, severity, z_score = self._zscore_analysis(baseline, value)

        if not is_anomaly:
            return None

        self.detection_count += 1
        self.anomaly_count += 1

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
            baseline_stdev=baseline.stdev,
        )

    def _store_raw(self, entity: str, metric: str, value: float):
        key = f"{entity}:{metric}"
        self.raw_data[key].append({
            'value': value,
            'timestamp': datetime.now()
        })

    def get_baseline(self, entity: str, metric: str) -> Optional[Baseline]:
        key = f"{entity}:{metric}"
        return self.baselines.get(key)

    def get_metrics(self) -> Dict:
        return {
            'baselines_count': len(self.baselines),
            'raw_data_entries': sum(len(v) for v in self.raw_data.values()),
            'detections': self.detection_count,
            'anomalies': self.anomaly_count,
            'ml_available': _ONNX_AVAILABLE and _ONNX_SESSION is not None,
        }
