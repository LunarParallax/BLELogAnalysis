"""Analyze RIC protocol command/response pairs."""

from typing import Dict, TextIO
from PacketInfo import PacketInfo
from dataclasses import dataclass


@dataclass
class CmdResp:
    """Container for command-response pair data.
    
    Attributes:
        msg_num: Message number identifier
        cmd_timestamp: Timestamp when command was sent
        cmd: Command payload bytes
        resp_timestamp: Timestamp when response was received
        resp: Response payload bytes
    """
    msg_num: int
    cmd_timestamp: float
    cmd: bytes
    resp_timestamp: float
    resp: bytes


class CmdRespAnalyzer:
    """Analyzes command-response message pairs for timing and tracking.
    
    Attributes:
        msg_tracker: Dictionary mapping message numbers to CmdResp objects
        outfile: Output file handle for logging results
    """
    
    def __init__(self, outfile: TextIO) -> None:
        """Initialize the analyzer.
        
        Args:
            outfile: File handle for writing output
        """
        self.msg_tracker: Dict[int, CmdResp] = {}
        self.outfile = outfile

    def ric_in_msg(self, msg, packet_info: PacketInfo) -> None:
        """Process incoming command message.
        
        Args:
            msg: Decoded message object with msgNum and payload attributes
            packet_info: Packet metadata (number, timestamp)
        """
        if msg.msg_num in self.msg_tracker:
            print(f"Repeat message {msg.msg_num}")
        else:
            self.msg_tracker[msg.msg_num] = CmdResp(
                msg_num=msg.msg_num,
                cmd_timestamp=packet_info.timestamp,
                cmd=msg.payload,
                resp_timestamp=0,
                resp=None
            )

    def ric_out_msg(self, msg, packet_info: PacketInfo) -> None:
        """Process outgoing response message.
        
        Args:
            msg: Decoded message object with msgNum and payload attributes
            packet_info: Packet metadata (number, timestamp)
        """
        if msg.msg_num not in self.msg_tracker:
            print(f"Spurious response {msg.msg_num}")
        else:
            cmd_resp = self.msg_tracker[msg.msg_num]
            cmd_resp.resp = msg.payload
            response_time_ms = round((packet_info.timestamp - cmd_resp.cmd_timestamp) * 1000, 1)
            self.outfile.write(f"CmdResp #{msg.msg_num} RespTime {response_time_ms}\n")
