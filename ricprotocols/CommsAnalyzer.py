"""Analyze RIC protocol communications from BLE captures."""

import pyshark
from typing import TextIO
from MsgHandler import MsgHandler
from PubMsgAnalyzer import PubMsgAnalyzer
from CmdRespAnalyzer import CmdRespAnalyzer
from martypy.RICProtocols import RICProtocols, DecodedMsg
from PacketInfo import PacketInfo


class CommsAnalyzer:
    """Analyzes RIC protocol communications over BLE.
    
    Attributes:
        in_msgs: Message handler for incoming messages
        out_msgs: Message handler for outgoing messages
        pub_msg_analyser: Analyzer for published messages
        cmd_resp_analyzer: Analyzer for command-response pairs
        outfile: Output file handle for logging
    """
    
    def __init__(self, outfile: TextIO) -> None:
        """Initialize the communications analyzer.
        
        Args:
            outfile: File handle for writing output
        """
        self.in_msgs = MsgHandler("IN", outfile, self._on_decoded_ric_in)
        self.out_msgs = MsgHandler("OUT", outfile, self._on_decoded_ric_out)
        self.pub_msg_analyser = PubMsgAnalyzer(outfile)
        self.cmd_resp_analyzer = CmdRespAnalyzer(outfile)
        self.outfile = outfile

    def ric_out_msg(self, msg: DecodedMsg, packet_info: PacketInfo) -> None:
        """Process outgoing message.
        
        Args:
            msg: Decoded message to process
            packet_info: Packet metadata
        """
        self.out_msgs.handle(msg, packet_info)

    def ric_in_msg(self, msg: DecodedMsg, packet_info: PacketInfo) -> None:
        """Process incoming message.
        
        Args:
            msg: Decoded message to process
            packet_info: Packet metadata
        """
        self.in_msgs.handle(msg, packet_info)

    def _on_decoded_ric_out(self, msg: DecodedMsg, packet_info: PacketInfo) -> None:
        """Handle decoded outgoing RIC message.
        
        Args:
            msg: Decoded RIC message
            packet_info: Packet metadata
        """
        if msg.protocol_id == RICProtocols.PROTOCOL_ROSSERIAL:
            if msg.msg_type_code == RICProtocols.MSG_TYPE_PUBLISH:
                self.pub_msg_analyser.handle_msg(msg, packet_info)
        elif msg.protocol_id == RICProtocols.PROTOCOL_RICREST:
            if msg.msg_type_code == RICProtocols.MSG_TYPE_RESPONSE:
                self.cmd_resp_analyzer.ric_out_msg(msg, packet_info)

    def _on_decoded_ric_in(self, msg: DecodedMsg, packet_info: PacketInfo) -> None:
        """Handle decoded incoming RIC message.
        
        Args:
            msg: Decoded RIC message
            packet_info: Packet metadata
        """
        if msg.protocol_id == RICProtocols.PROTOCOL_RICREST:
            if msg.msg_type_code == RICProtocols.MSG_TYPE_COMMAND:
                self.cmd_resp_analyzer.ric_in_msg(msg, packet_info)

    def show_stats(self) -> None:
        """Display communication statistics."""
        self.pub_msg_analyser.show_stats()



    