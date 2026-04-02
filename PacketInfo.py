"""Packet information data structure for BLE packet analysis."""

from dataclasses import dataclass


@dataclass
class PacketInfo:
    """Container for packet metadata.
    
    Attributes:
        num: Packet number in the capture file
        timestamp: Relative timestamp of the packet in seconds
    """
    num: int
    timestamp: float
