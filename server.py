"""
===============================================================================
Mini-WireGuard VPN: Tunnel Server (Windows)
===============================================================================
Role:
    Runs on Laptop 1 (Server). Creates a Layer 3 Wintun TUN adapter assigned to
    IP 10.8.0.1/24, listens on UDP port 51820, authenticates the client via an
    X25519 Noise-IK handshake, and relays encrypted raw IP packets between
    the OS network stack and the remote client.

Expected Deliverables Addressed:
    1. Real IP traffic tunneled through an authenticated encrypted channel
    2. Asymmetric authentication handshake and dynamic session key agreement
    3. Full-tunnel Internet relay via Windows NAT forwarding (--enable-nat)
    4. Seamless rekeying / session key rotation support

Usage:
    python server.py [--port 51820] [--enable-nat]
    (Must be run as Administrator)
===============================================================================
"""

import argparse
import ctypes
import socket
import subprocess
import sys
import threading
import time
from cryptography.hazmat.primitives.asymmetric import x25519

from wintun_adapter import WintunAdapter
from protocol import (
    ProtocolEngine,
    MSG_HANDSHAKE_INIT,
    MSG_DATA,
    deserialize_public_key,
    serialize_public_key,
)

# Ensure standard output is line-buffered for immediate console display
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

# =============================================================================
# Default Asymmetric Cryptographic Identities (WireGuard Style)
# =============================================================================
# Server's Static Private Key
DEFAULT_SERVER_PRIV_HEX = "a0b3e74cf2eec364d69ab0a16f87c1b1ef332801a5f18fbb8ae8f8f86025d467"
# Authorized Client's Static Public Key
DEFAULT_CLIENT_PUB_HEX  = "dfffdcf7c285107dbbf66bd0e66ba9458a11c9382b99228ffbf83094b5e34147"

TUN_IP = "10.8.0.1"
TUN_MASK = "255.255.255.0"
ADAPTER_NAME = "MiniWG-Server"


class MiniWireGuardServer:
    def __init__(self, bind_ip: str = "0.0.0.0", bind_port: int = 51820, enable_nat: bool = False):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.enable_nat = enable_nat

        # Load keys
        self.static_priv = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(DEFAULT_SERVER_PRIV_HEX))
        self.client_static_pub = deserialize_public_key(bytes.fromhex(DEFAULT_CLIENT_PUB_HEX))

        self.engine = ProtocolEngine(self.static_priv, self.client_static_pub)
        self.adapter = WintunAdapter(adapter_name=ADAPTER_NAME)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_endpoint = None  # (ip, port) of the authenticated client
        self.running = False

        # Stats
        self.packets_in = 0
        self.packets_out = 0
        self.bytes_in = 0
        self.bytes_out = 0

    def start(self):
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            print("[!] FATAL: This script must be run as Administrator to create the Wintun adapter.", file=sys.stderr)
            print("    Please right-click PowerShell or Command Prompt and select 'Run as administrator'.", file=sys.stderr)
            sys.exit(1)

        print("=" * 72)
        print(" [MINI-WIREGUARD SERVER] Starting Layer-3 Secure Tunnel")
        print("=" * 72)
        print(f" UDP Listener        : {self.bind_ip}:{self.bind_port}")
        print(f" TUN Virtual IP      : {TUN_IP} / 24")
        print(f" Server Public Key   : {serialize_public_key(self.static_priv.public_key()).hex()[:16]}...")
        print(f" Authorized Client   : {serialize_public_key(self.client_static_pub).hex()[:16]}...")

        # 1. Start Wintun Adapter
        print(f"[*] Initializing Wintun adapter '{ADAPTER_NAME}' with IP {TUN_IP}...")
        self.adapter.start(ip_address=TUN_IP, subnet_mask=TUN_MASK, peer_ip="10.8.0.2")
        print(f"[+] Wintun adapter active and assigned {TUN_IP}.")

        # Ensure Windows Defender Firewall allows incoming UDP traffic on bind_port
        try:
            subprocess.run(
                [
                    "powershell", "-Command",
                    f"if (-not (Get-NetFirewallRule -DisplayName 'MiniWireGuard-{self.bind_port}' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -DisplayName 'MiniWireGuard-{self.bind_port}' -Direction Inbound -LocalPort {self.bind_port} -Protocol UDP -Action Allow -ErrorAction SilentlyContinue | Out-Null }}; Enable-NetFirewallRule -DisplayName 'File and Printer Sharing (Echo Request - ICMPv4-In)' -ErrorAction SilentlyContinue"
                ],
                capture_output=True,
                check=False
            )
        except Exception:
            pass

        # 2. Setup Windows NAT / Forwarding if requested
        if self.enable_nat:
            self._setup_nat()

        # 3. Bind UDP socket
        self.sock.bind((self.bind_ip, self.bind_port))
        self.running = True

        print(f"[+] UDP socket bound to {self.bind_ip}:{self.bind_port}.")
        print("[+] Server ready for incoming client handshakes. Press Ctrl+C to stop.")
        print("=" * 72 + "\n")

        # Launch concurrent bidirectional relay threads
        t_udp = threading.Thread(target=self._udp_receive_loop, daemon=True)
        t_tun = threading.Thread(target=self._tun_read_loop, daemon=True)

        t_udp.start()
        t_tun.start()

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[INFO] KeyboardInterrupt received. Shutting down Mini-WireGuard Server...")
        finally:
            self.stop()

    def _setup_nat(self):
        """Enables IP forwarding and Windows NAT to allow full-tunnel Internet routing."""
        print("[*] Configuring Windows NAT for full-tunnel routing...")
        # Enable forwarding on all interfaces
        ps_forward = "Set-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue"
        subprocess.run(["powershell", "-Command", ps_forward], capture_output=True)

        # Create NAT rule for 10.8.0.0/24 subnet if it doesn't already exist
        ps_nat = (
            "Get-NetNat -Name 'MiniWG-NAT' -ErrorAction SilentlyContinue | Out-Null; "
            "if (-not $?) { New-NetNat -Name 'MiniWG-NAT' -InternalIPInterfaceAddressPrefix '10.8.0.0/24' -ErrorAction SilentlyContinue }"
        )
        subprocess.run(["powershell", "-Command", ps_nat], capture_output=True)
        print("[+] Windows NAT configured. Full-tunnel internet traffic can be relayed.")

    def _udp_receive_loop(self):
        """Receives incoming UDP datagrams, processes handshakes, and injects IP packets into TUN."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                if not data:
                    continue

                msg_type = data[0]

                # Case 1: Handshake Initiation (Client -> Server)
                if msg_type == MSG_HANDSHAKE_INIT:
                    print(f"\n[*] [HANDSHAKE INIT] Received initiation from {addr[0]}:{addr[1]}")
                    res = self.engine.process_handshake_init_and_respond(data)
                    if res:
                        resp_packet, session = res
                        self.client_endpoint = addr
                        self.sock.sendto(resp_packet, addr)
                        print(f"[+] [HANDSHAKE SUCCESS] Session #{session.session_id:08x} established with peer {addr[0]}:{addr[1]}")
                        print(f"    Symmetric AEAD   : ChaCha20-Poly1305 active")
                        print(f"    Tunnel Interface : Ready for routed IP traffic at {TUN_IP} <-> 10.8.0.2")
                    else:
                        print(f"[!] [HANDSHAKE REJECTED] Authentication or timestamp check failed from {addr[0]}:{addr[1]}")

                # Case 2: Encrypted Layer 3 IP Packet (Type 3)
                elif msg_type == MSG_DATA:
                    self.client_endpoint = addr  # Update roaming endpoint
                    decrypted_ip = self.engine.decrypt_ip_packet(data)
                    if decrypted_ip:
                        self.packets_in += 1
                        self.bytes_in += len(decrypted_ip)
                        print(f"[+] [RECV DATA #{self.packets_in}] {len(decrypted_ip)} bytes decrypted from {addr[0]}:{addr[1]} -> Injected into TUN")
                        # Inject raw IP packet into Windows OS network stack
                        self.adapter.write_packet(decrypted_ip)
                    else:
                        print(f"[ALERT] Dropped corrupt or unauthorized packet from {addr[0]}:{addr[1]}")

            except Exception as e:
                if self.running:
                    print(f"[ERROR] UDP receive error: {e}")

    def _tun_read_loop(self):
        """Reads outgoing IP packets from Wintun, encrypts them, and sends them to the client."""
        while self.running:
            try:
                ip_packet = self.adapter.read_packet(timeout_ms=50)
                if not ip_packet:
                    continue

                if self.client_endpoint and self.engine.current_session:
                    enc_packet = self.engine.encrypt_ip_packet(ip_packet)
                    if enc_packet:
                        self.sock.sendto(enc_packet, self.client_endpoint)
                        self.packets_out += 1
                        self.bytes_out += len(ip_packet)
                        print(f"[+] [SEND DATA #{self.packets_out}] {len(ip_packet)} bytes read from TUN -> Encrypted to {self.client_endpoint[0]}:{self.client_endpoint[1]}")

            except Exception as e:
                if self.running:
                    print(f"[ERROR] TUN read error: {e}")

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass
        try:
            self.adapter.close()
        except Exception:
            pass
        print(f"[INFO] Server stopped. Total IP Packets Relayed: In={self.packets_in}, Out={self.packets_out}")


def main():
    parser = argparse.ArgumentParser(description="Mini-WireGuard VPN Tunnel Server (Layer 3 Wintun)")
    parser.add_argument("--bind", default="0.0.0.0", help="UDP listen IP (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=51820, help="UDP listen port (default: 51820)")
    parser.add_argument("--enable-nat", action="store_true", help="Enable Windows NAT to route client's internet traffic")
    args = parser.parse_args()

    server = MiniWireGuardServer(bind_ip=args.bind, bind_port=args.port, enable_nat=args.enable_nat)
    server.start()


if __name__ == "__main__":
    main()
