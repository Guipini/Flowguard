"""
Runtime inference module.

Loads the trained Random Forest + calibrated threshold, and converts each
closed FlowRecord into an AlertDecision (what the dashboard renders).

Consumes: FlowRecord (from flow_builder).
Produces: AlertDecision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import joblib
import numpy as np

from flow_builder import FlowRecord


# ---------------------------------------------------------------------------
# Data contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertDecision:
    """What the detector emits for every closed flow."""
    flow_id: str
    timestamp: float               # end_ts of the flow (wall-clock)
    predicted_class: str           # model argmax: "benign" | "ddos" | "portscan"
    likely_attack_class: str       # argmax of non-benign classes only ("ddos" | "portscan")
    confidence: float              # probability of predicted class, 0.0 - 1.0
    attack_probability: float      # max(P(ddos), P(portscan)) - matches calibration
    severity: Literal["info", "alert"]
    flow_summary: FlowRecord       # denormalized for dashboard display


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class Detector:
    """
    Runs a trained model against live flows.

    Usage:
        det = Detector(Path('models'))
        for record in flow_builder.ingest(...):
            decision = det.predict(record)
            if decision.severity == 'alert':
                persist(decision)
    """

    def __init__(self, models_dir: Path) -> None:
        # Load artifacts
        self.model = joblib.load(models_dir / 'detector.pkl')
        metadata = json.loads((models_dir / 'metadata.json').read_text())
        self._feature_names: list[str] = metadata['feature_names']
        self._class_names:   list[str] = metadata['class_names']
        self._threshold:     float     = metadata['severity_thresholds']['alert_threshold']
        self._metadata = metadata

        self._validate_contract()

    # -- Public API --------------------------------------------------------

    def predict(self, flow: FlowRecord) -> AlertDecision:
        """Score a closed flow and return an AlertDecision."""
        vec = self._flow_to_vector(flow)
        probs = self.model.predict_proba(vec)[0]

        pred_idx = int(np.argmax(probs))
        pred_class = self._class_names[pred_idx]
        confidence = float(probs[pred_idx])

        # Attack probability uses the same metric we calibrated against
        # (max of the non-benign classes) - see notebook 04 cell 14.
        benign_idx = self._class_names.index('benign')
        attack_class_names = [c for i, c in enumerate(self._class_names) if i != benign_idx]
        attack_probs = np.delete(probs, benign_idx)
        attack_probability = float(attack_probs.max())
        likely_attack_class = attack_class_names[int(np.argmax(attack_probs))]

        severity = self._decide_severity(pred_class, attack_probability)

        return AlertDecision(
            flow_id=flow.flow_id,
            timestamp=flow.end_ts,
            predicted_class=pred_class,
            likely_attack_class=likely_attack_class,
            confidence=confidence,
            attack_probability=attack_probability,
            severity=severity,
            flow_summary=flow,
        )

    @property
    def feature_names(self) -> list[str]:
        """Debugging handle - lets capture.py log the contract on startup."""
        return list(self._feature_names)

    @property
    def threshold(self) -> float:
        return self._threshold

    # -- Internals ---------------------------------------------------------

    def _validate_contract(self) -> None:
        """Fail fast at startup if model / metadata / feature_names disagree."""
        n_model_features = int(getattr(self.model, 'n_features_in_', -1))
        if n_model_features != len(self._feature_names):
            raise ValueError(
                f"Feature-count mismatch: model expects {n_model_features} features, "
                f"metadata.feature_names lists {len(self._feature_names)}."
            )
        model_classes = [int(c) for c in self.model.classes_]
        expected_classes = list(range(len(self._class_names)))
        if model_classes != expected_classes:
            raise ValueError(
                f"Class-label mismatch: model.classes_={model_classes}, "
                f"metadata expects {expected_classes}."
            )
        if not 0.0 <= self._threshold <= 1.0:
            raise ValueError(f"Threshold out of range: {self._threshold}")

    def _flow_to_vector(self, flow: FlowRecord) -> np.ndarray:
        """Build the feature row in the exact order the model was trained on."""
        try:
            values = [float(getattr(flow, name)) for name in self._feature_names]
        except AttributeError as e:
            raise ValueError(
                f"FlowRecord is missing a feature the model needs: {e}. "
                "Check that flow_builder.FlowRecord has a field for every entry "
                "in metadata.feature_names."
            ) from None
        return np.array(values, dtype=np.float64).reshape(1, -1)

    def _decide_severity(self, predicted_class: str, attack_probability: float) -> Literal["info", "alert"]:
        """
        Decide whether this flow should raise an alert on the dashboard, or
        just be logged as informational.

        Inputs:
          predicted_class    : "benign" | "ddos" | "portscan" (model's argmax)
          attack_probability : max(P(ddos), P(portscan)) - matches what notebook 04
                               calibrated the threshold against

        Use `self._threshold` as the calibrated cutoff (read from metadata.json).
        """
        if attack_probability >= self._threshold:
            return "alert"
        return "info"


# ---------------------------------------------------------------------------
# Smoke test — `python src/detector.py`
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import sys

    MODELS_DIR = Path(__file__).resolve().parent.parent / 'models'
    det = Detector(MODELS_DIR)

    print('Loaded detector:')
    print(f'  feature_names ({len(det.feature_names)}): {det.feature_names[:3]}... {det.feature_names[-2:]}')
    print(f'  threshold:                {det.threshold:.4f}')
    print()

    # Construct three fake FlowRecords to exercise each severity path.
    # Values here are illustrative - real flows come from flow_builder.
    def make_flow(flow_id: str, **overrides) -> FlowRecord:
        base = dict(
            flow_id=flow_id, src_ip='127.0.0.1', dst_ip='127.0.0.2',
            src_port=40000, dst_port=80, protocol='tcp',
            start_ts=0.0, end_ts=1.0, close_reason='timeout',
            flow_duration=1_000_000.0,
            total_fwd_packets=4, total_backward_packets=3,
            flow_bytes_per_s=1000.0, flow_packets_per_s=7.0,
            fwd_packet_length_mean=60.0, bwd_packet_length_mean=80.0,
            average_packet_size=70.0,
            flow_iat_mean=100_000.0, flow_iat_std=10_000.0,
            syn_flag_count=1, ack_flag_count=5, fin_flag_count=2,
            rst_flag_count=0, psh_flag_count=2,
        )
        base.update(overrides)
        return FlowRecord(**base)

    # This looks like normal HTTP traffic → should predict benign
    benign_flow = make_flow('benign-demo')

    # This looks like a SYN flood: many small fwd packets, no backward, lots of SYN
    ddos_flow = make_flow(
        'ddos-demo',
        total_fwd_packets=500, total_backward_packets=0,
        fwd_packet_length_mean=40.0, bwd_packet_length_mean=0.0,
        average_packet_size=40.0,
        flow_bytes_per_s=20000.0, flow_packets_per_s=500.0,
        flow_iat_mean=2000.0, flow_iat_std=50.0,
        syn_flag_count=500, ack_flag_count=0, fin_flag_count=0,
        psh_flag_count=0,
    )

    # This looks like a port scan: single packet, tiny, RST received
    portscan_flow = make_flow(
        'portscan-demo',
        flow_duration=500.0,
        total_fwd_packets=1, total_backward_packets=1,
        fwd_packet_length_mean=40.0, bwd_packet_length_mean=40.0,
        average_packet_size=40.0,
        flow_bytes_per_s=80000.0, flow_packets_per_s=4000.0,
        flow_iat_mean=500.0, flow_iat_std=0.0,
        syn_flag_count=1, ack_flag_count=0, fin_flag_count=0,
        rst_flag_count=1, psh_flag_count=0,
        close_reason='rst',
    )

    for flow in (benign_flow, ddos_flow, portscan_flow):
        try:
            d = det.predict(flow)
        except NotImplementedError as e:
            print(f"!! {e}")
            sys.exit(1)
        print(f'{flow.flow_id}')
        print(f'  predicted: {d.predicted_class:<9}  confidence: {d.confidence:.3f}')
        print(f'  attack_prob: {d.attack_probability:.3f}  severity: {d.severity.upper()}')
        print()
