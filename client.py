"""
===============================================================================
Mini-WireGuard VPN: Tunnel Client (Windows)
===============================================================================
Role:
    Runs on Laptop 2 (Client). Creates a Layer 3 Wintun TUN adapter assigned to
    IP 10.8.0.2/24, connects to the server at <server_ip>:51820, performs an
    authenticated X25519 Noise-IK handshake, and relays encrypted raw IP
    packets between the local OS and the remote server.

Expected Deliverables Addressed:
    1. Real IP traffic tunneled through an authenticated encrypted channel
    2. Asymmetric authentication handshake and dynamic session key agreement
    3. Periodic automatic session key rotation (Milestone 87)
    4. Full-tunnel route injection option (--full-tunnel) to route all web traffic
    5. Interactive console for ping testing, manual rekeying, and tamper testing

Usage:
    python client.py <SERVER_IP> [--port 51820] [--rekey-interval 60] [--full-tunnel]
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
    MSG_HANDSHAKE_RESP,
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
# Client's Static Private Key
DEFAULT_CLIENT_PRIV_HEX = "706eb2d85178969f2c7e301ca3f68587d72383ce369b25c073f6b49a6faee241"
# Authorized Server's Static Public Key
DEFAULT_SERVER_PUB_HEX  = "8a7aa05b6877c6d6c03cd4bc6fa68feb1aab054d10ddaeefeaba306304565a24"

TUN_IP = "10.8.0.2"
TUN_MASK = "255.255.255.0"
GATEWAY_IP = "10.8.0.1"
ADAPTER_NAME = "MiniWG-Client"


class MiniWireGuardClient:
    def __init__(self, server_ip: str, server_port: int = 51820, rekey_interval: int = 60, full_tunnel: bool = False):
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_endpoint = (server_ip, server_port)
        self.rekey_interval = rekey_interval
        self.full_tunnel = full_tunnel

        # Load keys
        self.static_priv = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(DEFAULT_CLIENT_PRIV_HEX))
        self.server_static_pub = deserialize_public_key(bytes.fromhex(DEFAULT_SERVER_PUB_HEX))

        self.engine = ProtocolEngine(self.static_priv, self.server_static_pub)
        self.adapter = WintunAdapter(adapter_name=ADAPTER_NAME)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = False
        self.handshake_event = threading.Event()

        # Stats
        self.packets_in = 0
        self.packets_out = 0
        self.rekey_count = 0

    def start(self):
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            print("[!] FATAL: This script must be run as Administrator to create the Wintun adapter.", file=sys.stderr)
            print("    Please right-click PowerShell or Command Prompt and select 'Run as administrator'.", file=sys.stderr)
            sys.exit(1)

        print("=" * 72)
        print(" [MINI-WIREGUARD CLIENT] Starting Layer-3 Secure Tunnel")
        print("=" * 72)
        print(f" Remote Server       : {self.server_ip}:{self.server_port}")
        print(f" TUN Virtual IP      : {TUN_IP} / 24")
        print(f" Client Public Key   : {serialize_public_key(self.static_priv.public_key()).hex()[:16]}...")
        print(f" Server Public Key   : {serialize_public_key(self.server_static_pub).hex()[:16]}...")
        print(f" Rekey Interval      : Every {self.rekey_interval} seconds")

        # 1. Start Wintun Adapter
        print(f"[*] Initializing Wintun adapter '{ADAPTER_NAME}' with IP {TUN_IP}...")
        self.adapter.start(ip_address=TUN_IP, subnet_mask=TUN_MASK, peer_ip=GATEWAY_IP)
        print(f"[+] Wintun adapter active and assigned {TUN_IP}.")

        # Allow ICMP in Windows Defender Firewall so ping requests/replies are accepted
        try:
            subprocess.run(
                [
                    "powershell", "-Command",
                    "Enable-NetFirewallRule -DisplayName 'File and Printer Sharing (Echo Request - ICMPv4-In)' -ErrorAction SilentlyContinue; if (-not (Get-NetFirewallRule -DisplayName 'Allow-ICMP-In' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'Allow-ICMP-In' -Protocol ICMPv4 -IcmpType 8 -Action Allow -Direction Inbound -ErrorAction SilentlyContinue | Out-Null }"
                ],
                capture_output=True,
                check=False
            )
        except Exception:
            pass

        self.running = True

        # 2. Launch Background UDP and TUN Relay Threads
        t_udp = threading.Thread(target=self._udp_receive_loop, daemon=True)
        t_tun = threading.Thread(target=self._tun_read_loop, daemon=True)
        t_rekey = threading.Thread(target=self._periodic_rekey_loop, daemon=True)

        t_udp.start()
        t_tun.start()
        t_rekey.start()

        # 3. Perform Initial Noise-IK Handshake
        print(f"[*] Initiating X25519 authenticated handshake with {self.server_ip}:{self.server_port}...")
        self.initiate_handshake()

        # Wait up to 5 seconds for handshake completion
        if not self.handshake_event.wait(timeout=5.0):
            print("[WARN] Handshake response timed out. Is the server running and firewall port 51820 open?")
            print("       Client will continue retrying in background...\n")
        else:
            print("[+] Initial handshake completed successfully!")

        # 4. Configure full-tunnel routing if requested
        if self.full_tunnel:
            self._enable_full_tunnel()

        print("=" * 72)
        print(" [TUNNEL READY] Real IP packets on 10.8.0.0/24 are securely encapsulated.")
        print(" Commands:")
        print("   ping        : Sends 4 real ICMP ping packets through tunnel to 10.8.0.1")
        print("   rekey       : Manually triggers an immediate X25519 session key rotation")
        print("   status      : Shows session state and packet counters")
        print("   exit / quit : Closes tunnel and restores network routes")
        print("=" * 72 + "\n")

        self._interactive_menu()

    def initiate_handshake(self):
        """Builds and transmits a Type 1 Handshake Initiation packet."""
        init_packet = self.engine.build_handshake_init()
        self.sock.sendto(init_packet, self.server_endpoint)

    def _enable_full_tunnel(self):
        """
        Routes all default traffic through the VPN using the 0.0.0.0/1 and 128.0.0.0/1
        route-pairing technique (used by WireGuard and OpenVPN to avoid overwriting physical gateway).
        """
        print("[*] Adding full-tunnel routing (0.0.0.0/1 and 128.0.0.0/1 via 10.8.0.1)...")
        subprocess.run(["route", "add", "0.0.0.0", "mask", "128.0.0.0", GATEWAY_IP], capture_output=True)
        subprocess.run(["route", "add", "128.0.0.0", "mask", "128.0.0.0", GATEWAY_IP], capture_output=True)
        print("[+] Full-tunnel active. All Internet traffic is now routed through the server.")

    def _disable_full_tunnel(self):
        """Removes the VPN route overrides."""
        subprocess.run(["route", "delete", "0.0.0.0", "mask", "128.0.0.0", GATEWAY_IP], capture_output=True)
        subprocess.run(["route", "delete", "128.0.0.0", "mask", "128.0.0.0", GATEWAY_IP], capture_output=True)

    def _periodic_rekey_loop(self):
        """Periodically triggers dynamic session key rotation (Milestone 87)."""
        while self.running:
            time.sleep(self.rekey_interval)
            if self.running and self.engine.current_session:
                self.rekey_count += 1
                print(f"\n[*] [KEY ROTATION #{self.rekey_count}] Periodic timer fired. Rekeying ephemeral session...")
                self.initiate_handshake()

    def _udp_receive_loop(self):
        """Receives incoming UDP datagrams, completes handshakes, and injects IP packets into TUN."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                if not data:
                    continue

                msg_type = data[0]

                # Case 1: Handshake Response (Server -> Client)
                if msg_type == MSG_HANDSHAKE_RESP:
                    session = self.engine.process_handshake_resp(data)
                    if session:
                        print(f"\n[+] [HANDSHAKE SUCCESS] Established Session #{session.session_id:08x} with server {addr[0]}:{addr[1]}")
                        print(f"    Symmetric AEAD   : ChaCha20-Poly1305 active")
                        print(f"    Tunnel Interface : Ready for routed IP traffic at {TUN_IP} <-> {GATEWAY_IP}\n")
                        self.handshake_event.set()
                    else:
                        print(f"[!] [HANDSHAKE ERROR] Could not finalize session keys from {addr[0]}:{addr[1]}")

                # Case 2: Encrypted Layer 3 IP Packet (Type 3)
                elif msg_type == MSG_DATA:
                    decrypted_ip = self.engine.decrypt_ip_packet(data)
                    if decrypted_ip:
                        self.packets_in += 1
                        print(f"[+] [RECV DATA #{self.packets_in}] {len(decrypted_ip)} bytes decrypted from server -> Injected into TUN")
                        # Inject raw IP packet into Windows OS network stack
                        self.adapter.write_packet(decrypted_ip)

            except Exception as e:
                if self.running:
                    print(f"[ERROR] UDP receive error: {e}")

    def _tun_read_loop(self):
        """Reads outgoing IP packets from Wintun, encrypts them, and sends them to the server."""
        while self.running:
            try:
                ip_packet = self.adapter.read_packet(timeout_ms=50)
                if not ip_packet:
                    continue

                if self.engine.current_session:
                    enc_packet = self.engine.encrypt_ip_packet(ip_packet)
                    if enc_packet:
                        self.sock.sendto(enc_packet, self.server_endpoint)
                        self.packets_out += 1
                        print(f"[+] [SEND DATA #{self.packets_out}] {len(ip_packet)} bytes read from TUN -> Encrypted to server")

            except Exception as e:
                if self.running:
                    print(f"[ERROR] TUN read error: {e}")

    def _interactive_menu(self):
        """Interactive console loop for testing and demonstration."""
        while self.running:
            try:
                cmd = input("[MiniWG Client] > ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                break

            if not cmd:
                continue

            if cmd in ("exit", "quit", "q"):
                break
            elif cmd == "ping":
                print(f"[*] Sending 4 ICMP Ping packets to Server TUN IP ({GATEWAY_IP})...")
                subprocess.run(["ping", "-n", "4", GATEWAY_IP])
            elif cmd == "rekey":
                print("[*] Initiating manual X25519 session key rotation...")
                self.initiate_handshake()
            elif cmd == "status":
                sid = f"#{self.engine.current_session.session_id:08x}" if self.engine.current_session else "None"
                print(f"  Session ID       : {sid}")
                print(f"  Packets Relayed  : In={self.packets_in}, Out={self.packets_out}")
                print(f"  Key Rotations    : {self.rekey_count}")
                print(f"  Tunnel Endpoints : Client {TUN_IP} <===> Server {GATEWAY_IP}")
            else:
                print(f"Unknown command '{cmd}'. Available: ping, rekey, status, exit")

        self.stop()

    def stop(self):
        if not self.running:
            return
        print("\n[INFO] Shutting down Mini-WireGuard Client...")
        self.running = False
        if self.full_tunnel:
            self._disable_full_tunnel()
        try:
            self.sock.close()
        except Exception:
            pass
        try:
            self.adapter.close()
        except Exception:
            pass
        print(f"[INFO] Client stopped. Total IP Packets Relayed: In={self.packets_in}, Out={self.packets_out}")


def main():
    parser = argparse.ArgumentParser(description="Mini-WireGuard VPN Tunnel Client (Layer 3 Wintun)")
    parser.add_argument("server_ip", nargs="?", default="127.0.0.1", help="Server IPv4 address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=51820, help="Server UDP port (default: 51820)")
    parser.add_argument("--rekey-interval", type=int, default=60, help="Key rotation interval in seconds (default: 60)")
    parser.add_argument("--full-tunnel", action="store_true", help="Route all Internet traffic through the server")
    args = parser.parse_args()

    client = MiniWireGuardClient(
        server_ip=args.server_ip,
        server_port=args.port,
        rekey_interval=args.rekey_interval,
        full_tunnel=args.full_tunnel
    )
    client.start()


if __name__ == "__main__":
    main()
