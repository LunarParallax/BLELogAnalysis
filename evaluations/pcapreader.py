"""Read and parse pcap files using scapy."""

import sys
from typing import List
from scapy.all import rdpcap


def parse_pcap(pcap_path: str, urls_file: str) -> None:
    """Parse a pcap file and extract information.
    
    Args:
        pcap_path: Path to the pcap/pcapng file
        urls_file: Output file path (currently unused)
    """
    pcap_flow = rdpcap(pcap_path)
    sessions = pcap_flow.sessions()
    
    for session in sessions:
        for packet in sessions[session]:
            print(packet.show())


def main(arguments: List[str]) -> None:
    """Main entry point.
    
    Args:
        arguments: Command line arguments (currently uses hardcoded path)
    """
    # Example usage with hardcoded path
    pcap_path = r"C:\Users\rob\Downloads\Asus C232N WebApp Rev5 v1.2.46 + 1st Attempt.pcapng"
    output_file = "test.txt"
    parse_pcap(pcap_path, output_file)


if __name__ == "__main__":
    main(sys.argv)
