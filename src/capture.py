"""
capture.py - live packet capture + inference pipeline (runtime entry point).

Three-thread architecture (backend-architect-approved):
  T1 sniff_thread:    Scapy sniff(prn=...) -> push packets into packet_queue
  T2 infer_thread:    pull packets -> FlowBuilder -> Detector -> push AlertDecisions
  T3 persist_thread:  pull AlertDecisions -> SQLite writer (WAL mode)

Why threaded: Scapy's sniff callback blocks the receive loop. Pushing raw
packets into a bounded queue decouples capture rate from inference speed,
so a slow model.predict() can't drop incoming packets.

Usage (run from project root, in an ADMIN shell with venv activated):
    python src/capture.py
    python src/capture.py --iface "\\Device\\NPF_Loopback" --bpf "ip"
    python src/capture.py --db custom_alerts.db

Must run as Administrator on Windows + have Npcap with "Support loopback" enabled.
"""

from __future__ import annotations

import argparse
import queue
import signal
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from scapy.layers.inet import IP
from scapy.sendrecv import sniff

from detector import AlertDecision, Detector
from flow_builder import FlowBuilder, FlowRecord

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR   = PROJECT_ROOT / 'models'
DEFAULT_DB   = PROJECT_ROOT / 'alerts.db'

PACKET_QUEUE_MAX = 10_000
ALERT_QUEUE_MAX  = 1_000
FLUSH_INTERVAL_S = 5.0      # how often to call flow_builder.flush_expired()
STATS_INTERVAL_S = 10.0     # how often to print a status line

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    predicted_class TEXT NOT NULL,
    likely_attack_class TEXT,
    confidence REAL NOT NULL,
    attack_probability REAL NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
    protocol TEXT, packet_count INTEGER, byte_count INTEGER,
    close_reason TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
"""


@dataclass
class Stats:
    packets_captured:  int = 0
    packets_dropped:   int = 0   # packet_queue overflow
    flows_closed:      int = 0
    alerts_persisted:  int = 0
    critical_alerts:   int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                'packets_captured': self.packets_captured,
                'packets_dropped':  self.packets_dropped,
                'flows_closed':     self.flows_closed,
                'alerts_persisted': self.alerts_persisted,
                'critical_alerts':  self.critical_alerts,
            }


# ---------------------------------------------------------------------------
# Thread 1: sniff (Scapy)
# ---------------------------------------------------------------------------

def sniff_thread(
    stop_event: threading.Event,
    iface: str | None,
    bpf: str | None,
    packet_queue: queue.Queue,
    stats: Stats,
) -> None:
    """Scapy sniff loop. Pushes into packet_queue; drops on overflow."""
    def on_packet(pkt) -> None:
        if stop_event.is_set():
            return
        # Fast path: keep only IP-bearing packets. Non-IP noise (ARP, LLDP, etc.)
        # is irrelevant for flow analysis.
        if IP not in pkt:
            return
        try:
            packet_queue.put_nowait(pkt)
            with stats.lock:
                stats.packets_captured += 1
        except queue.Full:
            with stats.lock:
                stats.packets_dropped += 1
            # Silently drop — infer thread is behind, backpressure is working.

    # stop_filter makes sniff() return when stop_event fires (avoids needing
    # to kill the thread externally).
    def stop_filter(_pkt) -> bool:
        return stop_event.is_set()

    try:
        sniff(
            iface=iface,
            filter=bpf,
            prn=on_packet,
            store=False,          # don't accumulate in memory — we already forward
            stop_filter=stop_filter,
        )
    except PermissionError:
        print('ERROR: sniff requires Administrator privileges on Windows.', file=sys.stderr)
        print('       Close this terminal and re-open as Administrator.', file=sys.stderr)
        stop_event.set()
    except OSError as e:
        if 'Npcap' in str(e) or 'winpcap' in str(e).lower():
            print('ERROR: Npcap not found or unavailable.', file=sys.stderr)
            print('       Install Npcap from https://nmap.org/npcap/ with the', file=sys.stderr)
            print('       "Support loopback traffic" checkbox enabled.', file=sys.stderr)
        else:
            print(f'ERROR in sniff(): {e}', file=sys.stderr)
        stop_event.set()


# ---------------------------------------------------------------------------
# Thread 2: infer (FlowBuilder + Detector)
# ---------------------------------------------------------------------------

def infer_thread(
    stop_event: threading.Event,
    packet_queue: queue.Queue,
    alert_queue: queue.Queue,
    flow_builder: FlowBuilder,
    detector: Detector,
    stats: Stats,
) -> None:
    """Consume packets, aggregate into flows, score closed flows."""
    last_flush = time.monotonic()
    while not stop_event.is_set():
        try:
            pkt = packet_queue.get(timeout=1.0)
        except queue.Empty:
            pkt = None

        if pkt is not None:
            record = flow_builder.ingest(pkt)
            if record is not None:
                _score_and_emit(record, detector, alert_queue, stats)

        # Periodic idle-timeout sweep
        now = time.monotonic()
        if now - last_flush >= FLUSH_INTERVAL_S:
            for record in flow_builder.flush_expired(now):
                _score_and_emit(record, detector, alert_queue, stats)
            last_flush = now

    # Final drain: emit anything still in the flow table so we don't lose
    # half-closed flows on shutdown.
    for record in flow_builder.flush_expired(time.monotonic() + 999_999):
        _score_and_emit(record, detector, alert_queue, stats)


def _score_and_emit(
    record: FlowRecord,
    detector: Detector,
    alert_queue: queue.Queue,
    stats: Stats,
) -> None:
    try:
        decision = detector.predict(record)
    except Exception as e:
        print(f'WARN: detector.predict() failed on {record.flow_id}: {e}', file=sys.stderr)
        return

    with stats.lock:
        stats.flows_closed += 1
        if decision.severity == 'alert':
            stats.critical_alerts += 1

    try:
        alert_queue.put(decision, timeout=2.0)
    except queue.Full:
        print(f'WARN: alert_queue full, dropping {decision.flow_id}', file=sys.stderr)


# ---------------------------------------------------------------------------
# Thread 3: persist (SQLite writer)
# ---------------------------------------------------------------------------

def persist_thread(
    stop_event: threading.Event,
    alert_queue: queue.Queue,
    db_path: Path,
    stats: Stats,
) -> None:
    """Single-writer SQLite thread. WAL mode enables concurrent dashboard reads."""
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.executescript(SCHEMA)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')

    # Auto-migrate: add any columns that exist in the code but not in an
    # older DB. SQLite raises OperationalError if the column already exists;
    # we catch that and continue. Keeps upgrades frictionless.
    _migrations = [
        ('alerts', 'likely_attack_class', 'TEXT'),
    ]
    for table, col, coltype in _migrations:
        try:
            conn.execute(f'ALTER TABLE {table} ADD COLUMN {col} {coltype}')
        except sqlite3.OperationalError:
            pass  # column already present
    conn.commit()

    insert_sql = """
        INSERT INTO alerts (
            flow_id, timestamp, predicted_class, likely_attack_class,
            confidence, attack_probability,
            severity, src_ip, dst_ip, src_port, dst_port, protocol,
            packet_count, byte_count, close_reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    while not stop_event.is_set() or not alert_queue.empty():
        try:
            decision: AlertDecision = alert_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        flow = decision.flow_summary
        try:
            conn.execute(insert_sql, (
                decision.flow_id,
                decision.timestamp,
                decision.predicted_class,
                decision.likely_attack_class,
                decision.confidence,
                decision.attack_probability,
                decision.severity,
                flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port,
                flow.protocol,
                flow.total_fwd_packets + flow.total_backward_packets,
                int(flow.flow_bytes_per_s * (flow.flow_duration / 1_000_000)),
                flow.close_reason,
            ))
            conn.commit()
            with stats.lock:
                stats.alerts_persisted += 1
        except sqlite3.Error as e:
            print(f'WARN: SQLite insert failed: {e}', file=sys.stderr)

    conn.close()


# ---------------------------------------------------------------------------
# Stats reporter
# ---------------------------------------------------------------------------

def stats_thread(stop_event: threading.Event, stats: Stats) -> None:
    """Periodic one-line status report to stdout."""
    while not stop_event.wait(STATS_INTERVAL_S):
        s = stats.snapshot()
        print(
            f'[stats] captured={s["packets_captured"]:,} '
            f'dropped={s["packets_dropped"]:,} '
            f'flows_closed={s["flows_closed"]:,} '
            f'alerts={s["critical_alerts"]:,} '
            f'persisted={s["alerts_persisted"]:,}',
            flush=True,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description='Live anomaly detector capture pipeline.')
    ap.add_argument('--iface', default=None,
                    help=r'Interface to sniff (e.g. "\Device\NPF_Loopback"). Defaults to Scapy auto-select.')
    ap.add_argument('--bpf', default='ip',
                    help='Berkeley Packet Filter expression (default: "ip").')
    ap.add_argument('--db', default=str(DEFAULT_DB), type=Path,
                    help=f'SQLite database path (default: {DEFAULT_DB.name}).')
    ap.add_argument('--threshold', type=float, default=None,
                    help='Override the calibrated alert threshold from metadata.json. '
                         'Typical runtime values: 0.05 (loopback demo), 0.1322 (CICIDS2017-calibrated).')
    args = ap.parse_args()

    print(f'Loading detector from {MODELS_DIR} ...')
    detector = Detector(MODELS_DIR, threshold_override=args.threshold)
    if args.threshold is not None:
        print(f'  features: {len(detector.feature_names)}  threshold: {detector.threshold:.4f} '
              f'(overridden; calibrated was {detector._calibrated_threshold:.4f})')
    else:
        print(f'  features: {len(detector.feature_names)}  threshold: {detector.threshold:.4f}')

    flow_builder = FlowBuilder(idle_timeout_s=60.0)
    packet_queue: queue.Queue = queue.Queue(maxsize=PACKET_QUEUE_MAX)
    alert_queue:  queue.Queue = queue.Queue(maxsize=ALERT_QUEUE_MAX)
    stats = Stats()
    stop_event = threading.Event()

    threads = [
        threading.Thread(target=sniff_thread,
                         args=(stop_event, args.iface, args.bpf, packet_queue, stats),
                         name='sniff',   daemon=True),
        threading.Thread(target=infer_thread,
                         args=(stop_event, packet_queue, alert_queue, flow_builder, detector, stats),
                         name='infer',   daemon=True),
        threading.Thread(target=persist_thread,
                         args=(stop_event, alert_queue, args.db, stats),
                         name='persist', daemon=False),
        threading.Thread(target=stats_thread,
                         args=(stop_event, stats),
                         name='stats',   daemon=True),
    ]

    def shutdown(signum, frame) -> None:
        print('\nShutting down... (draining queues)', flush=True)
        stop_event.set()

    signal.signal(signal.SIGINT, shutdown)

    print(f'Starting capture -> {args.db}')
    print(f'  iface: {args.iface or "auto"}   bpf: {args.bpf!r}')
    print('Press Ctrl+C to stop.\n')

    for t in threads:
        t.start()

    # Block main thread until the persist thread (non-daemon) finishes draining.
    persist = next(t for t in threads if t.name == 'persist')
    try:
        while persist.is_alive():
            persist.join(timeout=0.5)
    except KeyboardInterrupt:
        shutdown(None, None)
        persist.join(timeout=5.0)

    final = stats.snapshot()
    print(f'\nFinal stats: {final}')
    print(f'Flow builder state: {flow_builder.stats()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
