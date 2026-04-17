"""
attack_simulator.py - traffic generator for end-to-end detector demos.

Sends attack-shaped TCP traffic at 127.0.0.1 to exercise the capture pipeline.
Must run in an Administrator shell (raw-socket send requires it on Windows).

Attack modes:
  syn_flood : rapid SYNs to a target port, random source ports.
              Simulates a volumetric SYN flood. Each SYN creates a short
              flow (kernel RSTs back), producing many alert-worthy flows.
  port_scan : single SYN to each port in a range, sequential, single source.
              Simulates a reconnaissance scan.

SAFETY: this script refuses any target that is not a loopback address.
Do NOT patch that check to point at external hosts - this is educational.

Usage (from project root, in Administrator shell with venv activated):
    python src/attack_simulator.py --attack syn_flood --rate 50 --count 500
    python src/attack_simulator.py --attack port_scan --rate 100
"""

from __future__ import annotations

import argparse
import random
import sys
import time

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

# ---------------------------------------------------------------------------

LOOPBACK_PREFIXES = ('127.', '::1')


def _rate_pacer(rate: float):
    """Drift-corrected pacer. Call `pacer.wait()` after each send."""
    class Pacer:
        def __init__(self, rate: float) -> None:
            self.interval = 1.0 / rate
            self.next_time = time.monotonic()

        def wait(self) -> None:
            self.next_time += self.interval
            sleep = self.next_time - time.monotonic()
            if sleep > 0:
                time.sleep(sleep)
    return Pacer(rate)


# ---------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------

def syn_flood(target: str, port: int, rate: float, count: int) -> None:
    """Send `count` SYN packets to `target:port` at `rate` pps.

    Each packet uses a fresh random source port, so the kernel's RST response
    arrives on a different 5-tuple - the capture pipeline sees many short
    flows (1 SYN fwd + 1 RST bwd), which is the observable signature of a
    spoofed-source SYN flood.
    """
    print(f'[syn_flood] target={target}:{port}  rate={rate}/s  count={count}', flush=True)
    pacer = _rate_pacer(rate)
    for i in range(count):
        src_port = random.randint(1024, 65535)
        pkt = IP(src=target, dst=target) / TCP(sport=src_port, dport=port, flags='S')
        send(pkt, verbose=False)
        if (i + 1) % 100 == 0:
            print(f'  sent {i + 1:>5}/{count}', flush=True)
        pacer.wait()
    print(f'[syn_flood] done: {count} SYNs sent to {target}:{port}', flush=True)


def port_scan(target: str, start_port: int, end_port: int, rate: float, src_port: int) -> None:
    """SYN one packet at each dst port in [start_port, end_port] from a single src_port.

    The kernel responds RST for every closed port, so each destination port
    becomes its own short flow (1 SYN fwd + 1 RST bwd). A sweep over ~1000
    ports at rate=100/s takes ~10 seconds.
    """
    ports = list(range(start_port, end_port + 1))
    print(f'[port_scan] target={target}  ports={start_port}-{end_port} '
          f'({len(ports)} ports)  rate={rate}/s  src_port={src_port}', flush=True)
    pacer = _rate_pacer(rate)
    for i, dst_port in enumerate(ports):
        pkt = IP(src=target, dst=target) / TCP(sport=src_port, dport=dst_port, flags='S')
        send(pkt, verbose=False)
        if (i + 1) % 100 == 0:
            print(f'  scanned {i + 1:>4}/{len(ports)} ports', flush=True)
        pacer.wait()
    print(f'[port_scan] done: {len(ports)} ports scanned on {target}', flush=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description='Attack traffic generator for detector demos (loopback only).',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument('--attack', required=True, choices=['syn_flood', 'port_scan'])
    ap.add_argument('--target', default='127.0.0.1', help='Loopback address')
    ap.add_argument('--rate', type=float, default=50.0, help='Packets per second')
    # syn_flood args
    ap.add_argument('--port', type=int, default=9999, help='[syn_flood] target port')
    ap.add_argument('--count', type=int, default=500, help='[syn_flood] packet count')
    # port_scan args
    ap.add_argument('--start-port', type=int, default=20, help='[port_scan] first port')
    ap.add_argument('--end-port', type=int, default=1024, help='[port_scan] last port')
    ap.add_argument('--src-port', type=int, default=54321, help='[port_scan] source port')
    args = ap.parse_args()

    # Safety: hard-block non-loopback targets.
    if not any(args.target.startswith(p) for p in LOOPBACK_PREFIXES):
        print(f'ERROR: target {args.target!r} is not a loopback address. Refusing to send.',
              file=sys.stderr)
        print('       This tool is educational; only 127.0.0.0/8 and ::1 are allowed.',
              file=sys.stderr)
        return 1

    # Rate sanity
    if args.rate <= 0 or args.rate > 2000:
        print(f'ERROR: --rate must be in (0, 2000], got {args.rate}', file=sys.stderr)
        return 1

    try:
        if args.attack == 'syn_flood':
            syn_flood(args.target, args.port, args.rate, args.count)
        elif args.attack == 'port_scan':
            port_scan(args.target, args.start_port, args.end_port, args.rate, args.src_port)
    except PermissionError:
        print('ERROR: raw-socket send requires Administrator privileges on Windows.',
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\n[interrupted]', file=sys.stderr)
        return 130
    return 0


if __name__ == '__main__':
    sys.exit(main())
