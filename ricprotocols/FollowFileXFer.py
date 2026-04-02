"""Follow and analyze file transfers from BLE captures."""

import pyshark
from CommsAnalyzer import CommsAnalyzer
from PacketInfo import PacketInfo
import logging
import os

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

BASE_FOLDER = r"C:\Users\rob\Downloads\blesniffs\202307BLETestLogs"


def analyze_file(filename: str) -> None:
    """Analyze a single pcapng file for file transfer data.
    
    Args:
        filename: Name of the pcapng file to analyze
    """
    fname, _ = os.path.splitext(filename)
    out_filename = os.path.join(BASE_FOLDER, f"{fname}.txt")
    
    with open(out_filename, "w") as outfile:
        cap = pyshark.FileCapture(os.path.join(BASE_FOLDER, filename), use_ek=True)
        comms_analyzer = CommsAnalyzer(outfile)

        for packet in cap:
            # Check if BT ATT protocol present
            if hasattr(packet, "btatt"):
                packet_info = PacketInfo(
                    num=packet.number,
                    timestamp=packet.frame_info.time.relative
                )
                
                opcode_method = packet.btatt.opcode.method
                
                if opcode_method == 2:  # MTU size
                    mtu_size = int(packet.btatt._fields_dict["btatt_btatt_client_rx_mtu"])
                    logger.info(f"MTU {mtu_size}")
                    
                elif opcode_method == 0x1b:  # Handle value notification
                    if hasattr(packet.btatt, "value"):
                        comms_analyzer.ric_out_msg(packet.btatt.value, packet_info)
                        
                elif opcode_method == 0x12:  # Write request
                    if hasattr(packet.btatt, "value"):
                        comms_analyzer.ric_in_msg(packet.btatt.value, packet_info)

        comms_analyzer.show_stats()


def main() -> None:
    """Process all pcapng files in the base folder."""
    slave_mac = "b8:d6:1a:bc:6e:96"
    
    # Iterate files in folder
    for filename in os.listdir(BASE_FOLDER):
        if filename.endswith(".pcapng"):
            analyze_file(filename)


if __name__ == "__main__":
    main()
