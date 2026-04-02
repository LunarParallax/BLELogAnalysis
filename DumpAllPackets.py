"""Dump all packets from a pcapng file using pyshark."""

import pyshark
import argparse


def dump_packets(filename: str) -> None:
    """Dump all packets from a capture file.
    
    Args:
        filename: Path to the pcapng capture file
    """
    with pyshark.FileCapture(filename, use_ek=True) as cap:
        for pkt in cap:
            pkt.show()


def main() -> None:
    """Main entry point for DumpAllPackets."""
    parser = argparse.ArgumentParser(
        description='Dump all packets from a pcapng file'
    )
    parser.add_argument(
        'filename',
        nargs='?',
        default='example.pcapng',
        help='pcapng file to analyze (default: example.pcapng)'
    )
    args = parser.parse_args()
    dump_packets(args.filename)


if __name__ == "__main__":
    main()
        