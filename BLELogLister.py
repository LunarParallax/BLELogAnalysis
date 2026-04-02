"""Display detailed pyshark packet information from pcapng files."""

import pyshark
import logging
import argparse
from typing import Optional

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def process_file(cap_file: str, start_pkt: Optional[int], num_pkts: Optional[int]) -> None:
    """Process a pcapng file and display packet information.
    
    Args:
        cap_file: Path to the pcapng capture file
        start_pkt: Starting packet number (1-indexed), or None to start from beginning
        num_pkts: Number of packets to process, or None for all packets
    """
    total_pkts = 0
    total_btle = 0
    total_with_btatt = 0
    packet_count = 0
    packets_processed = 0
    
    with pyshark.FileCapture(cap_file, use_ek=True) as cap:
        for pkt in cap:
            packet_count += 1
            
            # Skip packets before start_pkt
            if start_pkt is not None and packet_count < start_pkt:
                continue
            
            # Stop if we've processed enough packets
            if num_pkts is not None and packets_processed >= num_pkts:
                break
            
            # Format and display packet info
            pkt_str = str(pkt)
            pkt_str = pkt_str.replace("\r\n", "\n").replace("\n\r", "\n")
            pkt_str = pkt_str.replace("\n", "\n\t")
            pkt_str = "\t" + pkt_str
            pkt_str = pkt_str.rstrip("\t\n")
            
            print(f":\t ------------ pkt {packet_count} ------------")
            print(pkt_str)
            packets_processed += 1

            # Track protocol statistics
            if hasattr(pkt, "btatt"):
                total_with_btatt += 1
            if hasattr(pkt, "btle"):
                total_btle += 1
            total_pkts += 1
    
    print(f"Packets Total {total_pkts} BTATT {total_with_btatt} BTLE {total_btle}")


def main() -> None:
    """Main entry point for BLELogLister."""
    parser = argparse.ArgumentParser(
        description='Show pyshark packet info from pcapng files'
    )
    parser.add_argument(
        'filename',
        help='pcapng file to analyze'
    )
    parser.add_argument(
        "-s", "--start",
        type=int,
        help="Start packet number (1-indexed)"
    )
    parser.add_argument(
        "-n", "--num",
        default=10,
        type=int,
        help="Number of packets to process (default: 10)"
    )
    args = parser.parse_args()
    process_file(args.filename, args.start, args.num)


if __name__ == "__main__":
    main()
