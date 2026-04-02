"""Test live BLE capture using pyshark."""

import pyshark


def main() -> None:
    """Capture packets from a network interface for testing."""
    interface = 'eth0'
    timeout = 50
    
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=timeout)
    print(capture)


if __name__ == "__main__":
    main()
