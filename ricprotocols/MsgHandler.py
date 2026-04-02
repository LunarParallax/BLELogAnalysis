"""Message handler for processing HDLC-encoded RIC protocol messages."""

from typing import Callable, Optional, TextIO
from martypy import LikeHDLC, RICProtocols
from PacketInfo import PacketInfo


class MsgHandler:
    """Handles HDLC frame decoding and RIC protocol message processing.
    
    Attributes:
        hdlc: HDLC decoder instance
        ric_protocols: RIC protocols decoder
        on_msg: Callback function for decoded messages
        on_error: Optional callback function for errors
        last_packet_info: Most recent packet information
        prefix: Prefix string for output
        outfile: Output file handle for logging
    """
    
    def __init__(
        self,
        prefix: str,
        outfile: TextIO,
        on_msg: Callable,
        on_error: Optional[Callable] = None
    ) -> None:
        """Initialize the message handler.
        
        Args:
            prefix: Prefix string for output lines
            outfile: File handle for writing output
            on_msg: Callback function invoked when a message is decoded
            on_error: Optional callback function invoked on HDLC errors
        """
        self.hdlc = LikeHDLC.LikeHDLC(self._on_frame_rx, self._on_error)
        self.ric_protocols = RICProtocols.RICProtocols()
        self.on_msg = on_msg
        self._on_error_callback = on_error
        self.last_packet_info: Optional[PacketInfo] = None
        self.debug_in_frame = False
        self.debug_last_char_was_e7 = False
        self.debug_cur_line = ""
        self.prefix = prefix
        self.outfile = outfile
        self.debug_cur_hex = ""

    def _on_frame_rx(self, frame: bytes) -> None:
        """Handle received HDLC frame.
        
        Args:
            frame: Raw frame bytes received from HDLC decoder
        """
        msg = self.ric_protocols.decode_ric_frame(frame)
        if self.on_msg is not None:
            self.on_msg(msg, self.last_packet_info)

    def _on_error(self) -> None:
        """Handle HDLC decoding error."""
        self.outfile.write("<<CRC>>")
        if self._on_error_callback is not None:
            self._on_error_callback()

    def handle(self, msg: bytes, packet_info: PacketInfo) -> None:
        """Process a message byte-by-byte through the HDLC decoder.
        
        Args:
            msg: Message bytes to process
            packet_info: Packet metadata (number, timestamp)
        """
        self.last_packet_info = packet_info
        
        for byte in msg:
            self.debug_cur_hex += f"{byte:02x}"
            
            if byte == 0xe7:
                self.outfile.write("<<E7>>")
                if self.debug_last_char_was_e7 or not self.debug_in_frame:
                    self.debug_in_frame = True
                else:
                    if self.debug_in_frame:
                        self.outfile.write(f"{self.prefix} {self.debug_cur_hex}")
                        if self.debug_cur_line:
                            self.outfile.write(f" --- {self.debug_cur_line}\n")
                    self.debug_cur_line = ""
                    self.debug_cur_hex = ""
                    self.debug_in_frame = False
                self.debug_last_char_was_e7 = True
            else:
                if not self.debug_in_frame:
                    self.outfile.write("<@>")
                self.debug_last_char_was_e7 = False
            
            # Add printable character or '.' for non-printable
            self.debug_cur_line += chr(byte) if 32 < byte < 128 else '.'
            self.hdlc.decode_data(byte)
