"""
===============================================================================
Mini-WireGuard: Wintun Network Adapter Wrapper (Windows Layer 3 TUN)
===============================================================================
Provides an idiomatic Python ctypes interface to Wintun (wintun.dll),
the high-performance, official Layer 3 TUN driver developed by the WireGuard project.

Features:
    - Creates / opens persistent Wintun network interfaces
    - Configures IPv4 address, subnet mask, and interface metric via netsh
    - High-performance ring buffer session (4 MB default)
    - Event-driven non-blocking packet reception (WaitForSingleObject)
    - Thread-safe raw IP packet read and injection
    - Automatic graceful cleanup on termination
===============================================================================
"""

import ctypes
from ctypes import wintypes
import os
import subprocess
import sys
import time

# Windows constants
ERROR_ALREADY_EXISTS = 183
ERROR_NO_MORE_ITEMS = 259
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
INFINITE = 0xFFFFFFFF


class WintunAdapter:
    """Encapsulates a Wintun Layer 3 TUN interface on Windows."""

    def __init__(self, adapter_name: str = "MiniWireGuard", tunnel_type: str = "Wintun"):
        self.adapter_name = adapter_name
        self.tunnel_type = tunnel_type
        self.dll_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wintun.dll")
        
        if not os.path.exists(self.dll_path):
            raise FileNotFoundError(
                f"wintun.dll was not found at {self.dll_path}. "
                "Ensure wintun.dll (amd64) is in the same directory."
            )

        self._load_wintun_dll()
        self.adapter = None
        self.session = None
        self.read_event = None

    def _load_wintun_dll(self):
        """Loads wintun.dll and sets up function prototypes."""
        self.wintun = ctypes.WinDLL(self.dll_path)

        # WintunCreateAdapter
        self.wintun.WintunCreateAdapter.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p
        ]
        self.wintun.WintunCreateAdapter.restype = wintypes.HANDLE

        # WintunOpenAdapter
        self.wintun.WintunOpenAdapter.argtypes = [wintypes.LPCWSTR]
        self.wintun.WintunOpenAdapter.restype = wintypes.HANDLE

        # WintunCloseAdapter
        self.wintun.WintunCloseAdapter.argtypes = [wintypes.HANDLE]
        self.wintun.WintunCloseAdapter.restype = None

        # WintunStartSession
        self.wintun.WintunStartSession.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.wintun.WintunStartSession.restype = wintypes.HANDLE

        # WintunEndSession
        self.wintun.WintunEndSession.argtypes = [wintypes.HANDLE]
        self.wintun.WintunEndSession.restype = None

        # WintunGetReadWaitEvent
        self.wintun.WintunGetReadWaitEvent.argtypes = [wintypes.HANDLE]
        self.wintun.WintunGetReadWaitEvent.restype = wintypes.HANDLE

        # WintunReceivePacket
        self.wintun.WintunReceivePacket.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.wintun.WintunReceivePacket.restype = ctypes.POINTER(ctypes.c_ubyte)

        # WintunReleaseReceivePacket
        self.wintun.WintunReleaseReceivePacket.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ubyte)]
        self.wintun.WintunReleaseReceivePacket.restype = None

        # WintunAllocateSendPacket
        self.wintun.WintunAllocateSendPacket.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.wintun.WintunAllocateSendPacket.restype = ctypes.POINTER(ctypes.c_ubyte)

        # WintunSendPacket
        self.wintun.WintunSendPacket.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ubyte)]
        self.wintun.WintunSendPacket.restype = None

    def start(self, ip_address: str, subnet_mask: str = "255.255.255.0", peer_ip: str | None = None, ring_capacity: int = 0x400000):
        """
        Creates/opens the Wintun adapter, starts the session, and assigns an IP address.
        Requires Administrator privileges.
        """
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            raise PermissionError(
                "Administrator privileges are required to create/configure a TUN interface. "
                "Please run PowerShell or Command Prompt as Administrator."
            )

        # Create or open existing adapter
        self.adapter = self.wintun.WintunCreateAdapter(self.adapter_name, self.tunnel_type, None)
        if not self.adapter:
            err = ctypes.GetLastError()
            if err == ERROR_ALREADY_EXISTS:
                self.adapter = self.wintun.WintunOpenAdapter(self.adapter_name)
            if not self.adapter:
                raise OSError(f"Failed to create/open Wintun adapter '{self.adapter_name}' (WinError: {err})")

        # Start ring buffer session (default 4MB)
        self.session = self.wintun.WintunStartSession(self.adapter, ring_capacity)
        if not self.session:
            err = ctypes.GetLastError()
            raise OSError(f"Failed to start Wintun session (WinError: {err})")

        self.read_event = self.wintun.WintunGetReadWaitEvent(self.session)

        # Configure IP address, MTU, and peer routing
        self._configure_ip(ip_address, subnet_mask, peer_ip)
        return self

    def _configure_ip(self, ip_address: str, subnet_mask: str, peer_ip: str | None = None):
        """Configures the IPv4 address, MTU, and static neighbor on the Wintun adapter."""
        time.sleep(0.5)
        cmd = [
            "netsh", "interface", "ip", "set", "address",
            f"name={self.adapter_name}", "source=static",
            f"addr={ip_address}", f"mask={subnet_mask}"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0 and "already" not in res.stderr.lower():
            # Fallback retry with PowerShell NetTCPIP cmdlet
            ps_cmd = [
                "powershell", "-Command",
                f"New-NetIPAddress -InterfaceAlias '{self.adapter_name}' -IPAddress '{ip_address}' -PrefixLength 24 -ErrorAction SilentlyContinue"
            ]
            subprocess.run(ps_cmd, capture_output=True)

        # Set MTU to 1420 (WireGuard standard)
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "subinterface", self.adapter_name, "mtu=1420", "store=active"],
            capture_output=True
        )

        # On Layer-3 TUN adapters, Windows tries to resolve peers with ARP.
        # Adding a static neighbor entry prevents Windows from marking the peer 'Unreachable'.
        if peer_ip:
            subprocess.run(
                [
                    "netsh", "interface", "ip", "add", "neighbors",
                    f"interface={self.adapter_name}", f"address={peer_ip}", "neighbor=00-00-00-00-00-00", "store=active"
                ],
                capture_output=True
            )
            subprocess.run(
                ["route", "add", peer_ip, "mask", "255.255.255.255", ip_address],
                capture_output=True
            )

    def read_packet(self, timeout_ms: int = 20) -> bytes | None:
        """
        Reads a single raw Layer 3 IPv4/IPv6 packet from the TUN adapter.
        Checks ring buffer immediately first; only waits on event if empty.
        """
        if not self.session:
            return None

        packet_size = wintypes.DWORD(0)
        # 1. Immediately drain if a packet is already queued in the ring buffer
        packet_ptr = self.wintun.WintunReceivePacket(self.session, ctypes.byref(packet_size))
        if packet_ptr:
            try:
                return ctypes.string_at(packet_ptr, packet_size.value)
            finally:
                self.wintun.WintunReleaseReceivePacket(self.session, packet_ptr)

        # 2. If buffer is empty, wait for the read event to signal new incoming data
        status = ctypes.windll.kernel32.WaitForSingleObject(self.read_event, timeout_ms)
        if status == WAIT_TIMEOUT:
            return None

        packet_ptr = self.wintun.WintunReceivePacket(self.session, ctypes.byref(packet_size))
        if not packet_ptr:
            return None

        try:
            return ctypes.string_at(packet_ptr, packet_size.value)
        finally:
            self.wintun.WintunReleaseReceivePacket(self.session, packet_ptr)

    def write_packet(self, packet_bytes: bytes) -> bool:
        """
        Injects a raw Layer 3 IPv4/IPv6 packet into the OS network stack.
        Returns True on success.
        """
        if not self.session or not packet_bytes:
            return False

        size = len(packet_bytes)
        send_ptr = self.wintun.WintunAllocateSendPacket(self.session, size)
        if not send_ptr:
            return False

        ctypes.memmove(send_ptr, packet_bytes, size)
        self.wintun.WintunSendPacket(self.session, send_ptr)
        return True

    def close(self):
        """Ends the session and closes the adapter cleanly."""
        if self.session:
            self.wintun.WintunEndSession(self.session)
            self.session = None
        if self.adapter:
            self.wintun.WintunCloseAdapter(self.adapter)
            self.adapter = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

