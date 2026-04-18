"""
fATT-style metadata extraction using pyshark.

Usage:
  python tools/fatt_extract.py --pcap capture.pcapng --limit 200
  sudo python tools/fatt_extract.py --interface en0 --limit 100
"""

import argparse
import json
from collections import Counter

try:
    import pyshark
except ImportError as exc:
    raise SystemExit("Install dependency: pip install pyshark") from exc


def packet_iter(args):
    if args.pcap:
        return pyshark.FileCapture(args.pcap, keep_packets=False)
    return pyshark.LiveCapture(interface=args.interface)


def summarize(args):
    capture = packet_iter(args)
    protocol_counter = Counter()
    src_counter = Counter()
    dst_counter = Counter()
    fingerprints = []

    for idx, pkt in enumerate(capture):
        if idx >= args.limit:
            break
        highest = getattr(pkt, "highest_layer", "UNKNOWN")
        protocol_counter[highest] += 1

        ip_layer = getattr(pkt, "ip", None) or getattr(pkt, "ipv6", None)
        if ip_layer:
            src = getattr(ip_layer, "src", "unknown")
            dst = getattr(ip_layer, "dst", "unknown")
            src_counter[src] += 1
            dst_counter[dst] += 1

        transport = getattr(pkt, "transport_layer", None)
        ttl = getattr(getattr(pkt, "ip", None), "ttl", None)
        win = None
        if transport and hasattr(pkt, transport.lower()):
            layer = getattr(pkt, transport.lower())
            win = getattr(layer, "window_size_value", None)

        fingerprints.append(
            {
                "protocol": highest,
                "transport": transport,
                "ttl": ttl,
                "window_size": win,
            }
        )

    result = {
        "processed_packets": min(args.limit, sum(protocol_counter.values())),
        "top_protocols": protocol_counter.most_common(10),
        "top_sources": src_counter.most_common(10),
        "top_destinations": dst_counter.most_common(10),
        "fingerprints": fingerprints[:50],
    }
    print(json.dumps(result, indent=2))


def parse_args():
    parser = argparse.ArgumentParser(description="Extract metadata/fingerprints from traffic.")
    parser.add_argument("--pcap", help="Path to pcap/pcapng file")
    parser.add_argument("--interface", default="eth0", help="Interface for live capture")
    parser.add_argument("--limit", type=int, default=200, help="Maximum packets to process")
    args = parser.parse_args()
    if not args.pcap and not args.interface:
        raise SystemExit("Provide --pcap or --interface")
    return args


if __name__ == "__main__":
    summarize(parse_args())
