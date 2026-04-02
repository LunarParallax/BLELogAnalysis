"""Analyze published RIC ROSSerial messages."""

from typing import Dict, TextIO, List
from martypy import RICProtocols
from martypy.RICROSSerial import RICROSSerial
from PacketInfo import PacketInfo


class PubMsgAnalyzer:
    """Analyzes published ROSSerial messages and tracks timestamps.
    
    Attributes:
        pub_msg_timestamps: Dictionary mapping topic IDs to lists of timestamps
        last_pub_msg_time: Timestamp of the most recent published message
        outfile: Output file handle for logging
    """
    
    def __init__(self, outfile: TextIO) -> None:
        """Initialize the analyzer.
        
        Args:
            outfile: File handle for writing output
        """
        self.pub_msg_timestamps: Dict[int, List[float]] = {}
        self.last_pub_msg_time: float = 0.0
        self.outfile = outfile

    def handle_msg(self, msg: RICProtocols.DecodedMsg, packet_info: PacketInfo) -> None:
        """Process a published message.
        
        Args:
            msg: Decoded RIC protocol message
            packet_info: Packet metadata (number, timestamp)
        """
        self.last_pub_msg_time = packet_info.timestamp
        RICROSSerial.decode(msg.payload, 0, self._rx_published_msg)

    def _rx_published_msg(self, topic_id: int, payload: bytes) -> None:
        """Handle received published message.
        
        Args:
            topic_id: Topic identifier for the published message
            payload: Message payload bytes
        """
        if topic_id not in self.pub_msg_timestamps:
            self.pub_msg_timestamps[topic_id] = []
        self.pub_msg_timestamps[topic_id].append(self.last_pub_msg_time)

    def show_stats(self) -> None:
        """Display statistics about published messages."""
        stats = [f"{name}:{len(val)}" for name, val in self.pub_msg_timestamps.items()]
        print(f"PubMsgs {stats}")
