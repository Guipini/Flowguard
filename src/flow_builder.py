"""
5-tuple flow aggregator - turns Scapy packets into FlowRecord dataclasses.

Check: observe individual packets, group them into flows by 5-tuple
(src_ip, src_port, dst_ip, dst_port, protocol), maintain running statistics,
and emit an immutable FlowRecord when the flow terminates.

Only accepts Scapy packet objects and emits FlowRecords.

The FlowRecord fields mirror feature_names.json exactly - runtime inference
depends on this contract.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal, Optional

# Scapy types; imported here so flow_builder has no cross-module leakage.
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

# TCP flag bitmask constants (from RFC 793).
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


# ---------------------------------------------------------------------------
# Data contracts (must match the training-side feature names)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FlowKey:
    """Canonical 5-tuple. Packets in either direction produce the same key."""
    ip_a: str
    port_a: int
    ip_b: str
    port_b: int
    protocol: str  # "tcp" | "udp"

    @classmethod
    def from_endpoints(cls, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> "FlowKey":
        # Order-independent: whichever endpoint is lexicographically smaller is ip_a.
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if a <= b:
            return cls(src_ip, src_port, dst_ip, dst_port, protocol)
        return cls(dst_ip, dst_port, src_ip, src_port, protocol)


@dataclass(frozen=True)
class FlowRecord:
    """Immutable record emitted when a flow terminates. Ready for the detector."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_ts: float               # wall-clock (unix epoch)
    end_ts: float
    close_reason: str             # "fin" | "rst" | "timeout"
    # --- 15 features (must match feature_names.json ordering in detector.py) ---
    flow_duration: float          # microseconds
    total_fwd_packets: int
    total_backward_packets: int
    flow_bytes_per_s: float
    flow_packets_per_s: float
    fwd_packet_length_mean: float
    bwd_packet_length_mean: float
    average_packet_size: float
    flow_iat_mean: float          # microseconds
    flow_iat_std: float           # microseconds
    syn_flag_count: int
    ack_flag_count: int
    fin_flag_count: int
    rst_flag_count: int
    psh_flag_count: int


# ---------------------------------------------------------------------------
# Welford's online mean/variance (numerically stable, O(1) per update)
# ---------------------------------------------------------------------------


class Welford:
    """Running mean and standard deviation in constant memory."""

    __slots__ = ("n", "mean", "m2")

    def __init__(self) -> None:
        self.n: int = 0
        self.mean: float = 0.0
        self.m2: float = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2

    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return (self.m2 / self.n) ** 0.5


# ---------------------------------------------------------------------------
# In-progress flow state
# ---------------------------------------------------------------------------


@dataclass
class FlowState:
    key: FlowKey
    # Initiator = first endpoint seen. Direction of subsequent packets is
    # determined by comparing src to the initiator.
    initiator_ip: str
    initiator_port: int
    start_ts_wall: float          # wall-clock seconds (time.time())
    start_ts_mono: float          # monotonic seconds (time.monotonic()), deltas only
    last_pkt_ts_mono: float
    # Counters
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    # Running statistics
    fwd_lengths: Welford = field(default_factory=Welford)
    bwd_lengths: Welford = field(default_factory=Welford)
    all_lengths: Welford = field(default_factory=Welford)
    inter_arrival_us: Welford = field(default_factory=Welford)
    # TCP flag counters
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    # Graceful-close tracking (TCP): FIN seen in each direction
    fwd_fin_seen: bool = False
    bwd_fin_seen: bool = False

    def direction_of(self, src_ip: str, src_port: int) -> Literal["fwd", "bwd"]:
        if src_ip == self.initiator_ip and src_port == self.initiator_port:
            return "fwd"
        return "bwd"

def should_close_flow(
    state: FlowState,
    direction: Literal["fwd", "bwd"],
    saw_fin: bool,
    saw_rst: bool,
    now_mono: float,
    idle_timeout_s: float = 60.0,
) -> Optional[str]:
    """
    Decide whether the flow should terminate right now.

    This encodes TCP's connection-lifecycle semantics. It runs AFTER the new
    packet has been folded into `state` (counters incremented, stats updated),
    so `state` reflects the post-packet reality.

    Return one of:
      - 'rst'     : abrupt reset - one side sent RST
      - 'fin'     : graceful close - both sides have sent FIN
      - 'timeout' : no packets for longer than idle_timeout_s
      - None      : flow is still alive, keep accumulating
    """
    # 1. RST check → return 'rst' if applicable
    if saw_rst:
        return 'rst'
    
    # 2. FIN tracking + check → return 'fin' if applicable
    if saw_fin:
        if direction == 'fwd':
            state.fwd_fin_seen = True
        else:
            state.bwd_fin_seen = True
    
    if state.fwd_fin_seen and state.bwd_fin_seen:
        return 'fin'
    # 3. Timeout check → return 'timeout' if applicable
    if (now_mono - state.last_pkt_ts_mono) > idle_timeout_s:
        return 'timeout'
    # 4. Fall-through: flow is alive
    return None


# ---------------------------------------------------------------------------
# FlowBuilder — the state machine
# ---------------------------------------------------------------------------


class FlowBuilder:
    """
    Stateful 5-tuple aggregator.

    Usage:
        builder = FlowBuilder()
        for pkt in scapy_sniff():
            record = builder.ingest(pkt)
            if record is not None:
                detector.predict(record)
        for record in builder.flush_expired(time.monotonic()):
            detector.predict(record)
    """

    def __init__(self, idle_timeout_s: float = 60.0, max_flows: int = 5000) -> None:
        self._flows: dict[FlowKey, FlowState] = {}
        self._idle_timeout_s = idle_timeout_s
        self._max_flows = max_flows
        self._closed_count = 0
        self._dropped_count = 0
        self._non_ip_count = 0

    # -- Public API --------------------------------------------------------

    def ingest(self, pkt: Packet) -> Optional[FlowRecord]:
        """Process a single Scapy packet. Return a FlowRecord if a flow closed."""
        parsed = self._parse(pkt)
        if parsed is None:
            self._non_ip_count += 1
            return None

        src_ip, src_port, dst_ip, dst_port, protocol, pkt_len, flags = parsed
        now_mono = time.monotonic()
        now_wall = time.time()

        key = FlowKey.from_endpoints(src_ip, src_port, dst_ip, dst_port, protocol)
        state = self._flows.get(key)

        if state is None:
            if len(self._flows) >= self._max_flows:
                self._dropped_count += 1
                return None
            state = FlowState(
                key=key,
                initiator_ip=src_ip,
                initiator_port=src_port,
                start_ts_wall=now_wall,
                start_ts_mono=now_mono,
                last_pkt_ts_mono=now_mono,
            )
            self._flows[key] = state

        direction = state.direction_of(src_ip, src_port)

        # Update inter-arrival time (skip the first packet of a flow)
        if state.fwd_packets + state.bwd_packets > 0:
            iat_us = (now_mono - state.last_pkt_ts_mono) * 1_000_000
            state.inter_arrival_us.add(iat_us)
        state.last_pkt_ts_mono = now_mono

        # Update counters
        if direction == "fwd":
            state.fwd_packets += 1
            state.fwd_bytes += pkt_len
            state.fwd_lengths.add(pkt_len)
        else:
            state.bwd_packets += 1
            state.bwd_bytes += pkt_len
            state.bwd_lengths.add(pkt_len)
        state.all_lengths.add(pkt_len)

        # Update flag counters
        saw_fin = bool(flags & TCP_FIN)
        saw_rst = bool(flags & TCP_RST)
        if saw_fin:
            state.fin_count += 1
        if saw_rst:
            state.rst_count += 1
        if flags & TCP_SYN:
            state.syn_count += 1
        if flags & TCP_ACK:
            state.ack_count += 1
        if flags & TCP_PSH:
            state.psh_count += 1

        # Decide whether to close
        reason = should_close_flow(
            state,
            direction=direction,
            saw_fin=saw_fin,
            saw_rst=saw_rst,
            now_mono=now_mono,
            idle_timeout_s=self._idle_timeout_s,
        )
        if reason is not None:
            return self._close(key, state, now_wall, reason)
        return None

    def flush_expired(self, now_mono: float) -> list[FlowRecord]:
        """Close every flow idle longer than the timeout. Call periodically."""
        expired_keys = [
            k for k, s in self._flows.items()
            if (now_mono - s.last_pkt_ts_mono) > self._idle_timeout_s
        ]
        now_wall = time.time()
        records = []
        for k in expired_keys:
            state = self._flows[k]
            records.append(self._close(k, state, now_wall, "timeout"))
        return records

    def stats(self) -> dict:
        return {
            "active_flows": len(self._flows),
            "closed_flows": self._closed_count,
            "dropped_flows": self._dropped_count,
            "non_ip_packets": self._non_ip_count,
        }

    # -- Internals ---------------------------------------------------------

    def _parse(self, pkt: Packet) -> Optional[tuple]:
        """Extract 5-tuple + pkt length + TCP flags. Return None for non-TCP/UDP."""
        if IP not in pkt:
            return None
        ip_layer = pkt[IP]
        if TCP in pkt:
            t = pkt[TCP]
            return (ip_layer.src, int(t.sport), ip_layer.dst, int(t.dport),
                    "tcp", len(pkt), int(t.flags))
        if UDP in pkt:
            u = pkt[UDP]
            return (ip_layer.src, int(u.sport), ip_layer.dst, int(u.dport),
                    "udp", len(pkt), 0)
        return None

    def _close(self, key: FlowKey, state: FlowState, end_ts_wall: float, reason: str) -> FlowRecord:
        duration_us = max(0.0, (state.last_pkt_ts_mono - state.start_ts_mono) * 1_000_000)
        # Guard divisions by zero on micro-flows (one packet, zero duration)
        duration_s = duration_us / 1_000_000
        total_packets = state.fwd_packets + state.bwd_packets
        total_bytes = state.fwd_bytes + state.bwd_bytes

        record = FlowRecord(
            flow_id=self._flow_id(state),
            src_ip=state.initiator_ip,
            dst_ip=state.key.ip_b if state.initiator_ip == state.key.ip_a else state.key.ip_a,
            src_port=state.initiator_port,
            dst_port=state.key.port_b if state.initiator_port == state.key.port_a else state.key.port_a,
            protocol=state.key.protocol,
            start_ts=state.start_ts_wall,
            end_ts=end_ts_wall,
            close_reason=reason,
            flow_duration=duration_us,
            total_fwd_packets=state.fwd_packets,
            total_backward_packets=state.bwd_packets,
            flow_bytes_per_s=(total_bytes / duration_s) if duration_s > 0 else 0.0,
            flow_packets_per_s=(total_packets / duration_s) if duration_s > 0 else 0.0,
            fwd_packet_length_mean=state.fwd_lengths.mean,
            bwd_packet_length_mean=state.bwd_lengths.mean,
            average_packet_size=state.all_lengths.mean,
            flow_iat_mean=state.inter_arrival_us.mean,
            flow_iat_std=state.inter_arrival_us.std(),
            syn_flag_count=state.syn_count,
            ack_flag_count=state.ack_count,
            fin_flag_count=state.fin_count,
            rst_flag_count=state.rst_count,
            psh_flag_count=state.psh_count,
        )
        del self._flows[key]
        self._closed_count += 1
        return record

    @staticmethod
    def _flow_id(state: FlowState) -> str:
        return (
            f"{state.key.protocol}:{state.key.ip_a}:{state.key.port_a}"
            f"<->{state.key.ip_b}:{state.key.port_b}"
        )


# ---------------------------------------------------------------------------
# Smoke test - run `python src/flow_builder.py` to see flow aggregation in action
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    from scapy.layers.inet import IP as _IP, TCP as _TCP

    builder = FlowBuilder(idle_timeout_s=60.0)
    client, server = "127.0.0.1", "127.0.0.2"

    # A three-way handshake + data + graceful close
    packets = [
        _IP(src=client, dst=server) / _TCP(sport=40000, dport=80, flags="S"),
        _IP(src=server, dst=client) / _TCP(sport=80, dport=40000, flags="SA"),
        _IP(src=client, dst=server) / _TCP(sport=40000, dport=80, flags="A"),
        _IP(src=client, dst=server) / _TCP(sport=40000, dport=80, flags="PA") / b"GET / HTTP/1.1\r\n\r\n",
        _IP(src=server, dst=client) / _TCP(sport=80, dport=40000, flags="PA") / b"HTTP/1.1 200 OK\r\n\r\n",
        _IP(src=client, dst=server) / _TCP(sport=40000, dport=80, flags="FA"),
        _IP(src=server, dst=client) / _TCP(sport=80, dport=40000, flags="FA"),
    ]

    for i, p in enumerate(packets, 1):
        rec = builder.ingest(p)
        print(f"  pkt {i} ({p[_TCP].flags}): {'CLOSED' if rec else '...'}")
        if rec:
            print(f"    → flow_id={rec.flow_id} reason={rec.close_reason}")
            print(f"    → fwd={rec.total_fwd_packets} bwd={rec.total_backward_packets} "
                  f"bytes={int(rec.flow_bytes_per_s * (rec.flow_duration/1_000_000))}")
            print(f"    → syn={rec.syn_flag_count} ack={rec.ack_flag_count} "
                  f"fin={rec.fin_flag_count} rst={rec.rst_flag_count} psh={rec.psh_flag_count}")

    print(f"\nStats: {builder.stats()}")
