"""
===============================================================================
Mini-WireGuard Protocol & Cryptographic Engine
===============================================================================
Implements the core cryptographic primitives and WireGuard-inspired
Noise IK handshake for peer authentication, dynamic key agreement,
and authenticated data encapsulation.

Primitives:
    - Key Exchange: Curve25519 (X25519) Diffie-Hellman
    - Key Derivation: HKDF-SHA256
    - Symmetric Authenticated Encryption: ChaCha20-Poly1305 (RFC 8439)
    - Anti-Replay: Monotonic 64-bit sequence counters

Message Types:
    - 0x01: Handshake Initiation (Client -> Server)
    - 0x02: Handshake Response (Server -> Client)
    - 0x03: Encapsulated Layer 3 Data Packet (Bidirectional)
===============================================================================
"""

import os
import struct
import time
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

# Protocol Message Type Constants
MSG_HANDSHAKE_INIT = 1
MSG_HANDSHAKE_RESP = 2
MSG_DATA = 3

# Key Derivation Info strings
HKDF_SALT = b"MiniWireGuard-v1-HKDF-Salt"
HKDF_HANDSHAKE_INFO = b"MiniWireGuard-Handshake-Keys"


def generate_keypair():
    """Generates a static or ephemeral X25519 private/public keypair."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def serialize_public_key(pub_key: x25519.X25519PublicKey) -> bytes:
    """Serializes an X25519 public key to 32 raw bytes."""
    from cryptography.hazmat.primitives import serialization
    return pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def deserialize_public_key(raw_bytes: bytes) -> x25519.X25519PublicKey:
    """Deserializes 32 raw bytes back into an X25519 public key."""
    return x25519.X25519PublicKey.from_public_bytes(raw_bytes)


class SessionKeys:
    """Holds derived symmetric session keys for a single connection epoch."""
    def __init__(self, session_id: int, send_key: bytes, recv_key: bytes):
        self.session_id = session_id
        self.send_key = send_key
        self.recv_key = recv_key
        self.send_cipher = ChaCha20Poly1305(send_key)
        self.recv_cipher = ChaCha20Poly1305(recv_key)
        self.send_counter = 1
        self.created_at = time.time()


class ProtocolEngine:
    """Handles handshakes, key rotation, and packet encryption/decryption."""

    def __init__(self, static_priv: x25519.X25519PrivateKey, peer_static_pub: x25519.X25519PublicKey):
        self.static_priv = static_priv
        self.static_pub = static_priv.public_key()
        self.peer_static_pub = peer_static_pub
        
        self.current_session: SessionKeys | None = None
        self.previous_session: SessionKeys | None = None  # Grace period during key rotation
        
        # Pending handshake state
        self._pending_eph_priv: x25519.X25519PrivateKey | None = None
        self._pending_session_id: int | None = None

    # -------------------------------------------------------------------------
    # Handshake Initiation (Client -> Server)
    # -------------------------------------------------------------------------
    def build_handshake_init(self) -> bytes:
        """
        Builds a Type 1 Handshake Initiation packet:
          [1B Type=1] [4B SessionID] [32B Client EphPub] [12B Nonce] [Encrypted Payload + 16B Tag]
          Payload contains: [32B Client Static Pub] + [8B Timestamp]
        """
        self._pending_eph_priv, client_eph_pub = generate_keypair()
        self._pending_session_id = struct.unpack("<I", os.urandom(4))[0]

        # Ephemeral Diffie-Hellman with Server's static public key
        ss_init = self._pending_eph_priv.exchange(self.peer_static_pub)
        init_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=HKDF_SALT,
            info=b"MiniWireGuard-Init-Encrypt"
        ).derive(ss_init)

        # Encrypt client static identity and current timestamp
        nonce = os.urandom(12)
        payload = serialize_public_key(self.static_pub) + struct.pack("<d", time.time())
        ciphertext = ChaCha20Poly1305(init_key).encrypt(nonce, payload, None)

        msg = (
            struct.pack("<BI", MSG_HANDSHAKE_INIT, self._pending_session_id) +
            serialize_public_key(client_eph_pub) +
            nonce +
            ciphertext
        )
        return msg

    # -------------------------------------------------------------------------
    # Handshake Processing & Response (Server Side)
    # -------------------------------------------------------------------------
    def process_handshake_init_and_respond(self, raw_packet: bytes) -> tuple[bytes, SessionKeys] | None:
        """
        Processes a Type 1 Handshake Initiation packet on the server.
        Validates the client, derives session keys, and builds a Type 2 Response.
        """
        if len(raw_packet) < 1 + 4 + 32 + 12 + 40 + 16:
            return None

        msg_type, client_session_id = struct.unpack("<BI", raw_packet[:5])
        if msg_type != MSG_HANDSHAKE_INIT:
            return None

        client_eph_pub_bytes = raw_packet[5:37]
        nonce = raw_packet[37:49]
        encrypted_payload = raw_packet[49:]

        client_eph_pub = deserialize_public_key(client_eph_pub_bytes)

        # Derive initial decryption key
        ss_init = self.static_priv.exchange(client_eph_pub)
        init_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=HKDF_SALT,
            info=b"MiniWireGuard-Init-Encrypt"
        ).derive(ss_init)

        try:
            decrypted = ChaCha20Poly1305(init_key).decrypt(nonce, encrypted_payload, None)
        except InvalidTag:
            return None

        client_static_pub_bytes = decrypted[:32]
        timestamp = struct.unpack("<d", decrypted[32:40])[0]

        # Verify timestamp freshness (within 120 seconds to prevent replay attacks)
        if abs(time.time() - timestamp) > 120:
            return None

        # Verify client static key matches expected authorized peer
        if client_static_pub_bytes != serialize_public_key(self.peer_static_pub):
            return None

        # Server generates its ephemeral keypair
        server_eph_priv, server_eph_pub = generate_keypair()
        server_session_id = struct.unpack("<I", os.urandom(4))[0]

        # Triple Diffie-Hellman Key Exchange (WireGuard Noise IK pattern)
        ss1 = server_eph_priv.exchange(client_eph_pub)
        ss2 = self.static_priv.exchange(client_eph_pub)
        ss3 = server_eph_priv.exchange(self.peer_static_pub)
        combined_secret = ss1 + ss2 + ss3

        # Derive bidirectional session keys:
        # Server sends with s2c_key, Server receives with c2s_key
        derived_keys = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=HKDF_SALT,
            info=HKDF_HANDSHAKE_INFO
        ).derive(combined_secret)

        c2s_key = derived_keys[:32]
        s2c_key = derived_keys[32:]

        # Server session: Send with s2c_key, Recv with c2s_key
        new_session = SessionKeys(server_session_id, send_key=s2c_key, recv_key=c2s_key)

        # Build Type 2 Response Packet:
        # [1B Type=2] [4B Server Session ID] [4B Client Session ID] [32B Server EphPub] [16B Tag]
        resp_nonce = os.urandom(12)
        resp_tag = ChaCha20Poly1305(s2c_key).encrypt(resp_nonce, b"OK", None)

        response_packet = (
            struct.pack("<BII", MSG_HANDSHAKE_RESP, server_session_id, client_session_id) +
            serialize_public_key(server_eph_pub) +
            resp_nonce +
            resp_tag
        )

        self._activate_new_session(new_session)
        return response_packet, new_session

    # -------------------------------------------------------------------------
    # Handshake Finalization (Client Side)
    # -------------------------------------------------------------------------
    def process_handshake_resp(self, raw_packet: bytes) -> SessionKeys | None:
        """
        Processes a Type 2 Response on the client to finalize session key agreement.
        """
        if len(raw_packet) < 1 + 4 + 4 + 32 + 12 + 18:
            return None

        msg_type, server_session_id, client_session_id = struct.unpack("<BII", raw_packet[:9])
        if msg_type != MSG_HANDSHAKE_RESP or client_session_id != self._pending_session_id:
            return None

        server_eph_pub_bytes = raw_packet[9:41]
        nonce = raw_packet[41:53]
        resp_tag = raw_packet[53:]

        server_eph_pub = deserialize_public_key(server_eph_pub_bytes)

        # Mirror the triple Diffie-Hellman operations
        ss1 = self._pending_eph_priv.exchange(server_eph_pub)
        ss2 = self._pending_eph_priv.exchange(self.peer_static_pub)
        ss3 = self.static_priv.exchange(server_eph_pub)
        combined_secret = ss1 + ss2 + ss3

        derived_keys = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=HKDF_SALT,
            info=HKDF_HANDSHAKE_INFO
        ).derive(combined_secret)

        c2s_key = derived_keys[:32]
        s2c_key = derived_keys[32:]

        # Client session: Send with c2s_key, Recv with s2c_key
        try:
            # Authenticate the server response tag
            ChaCha20Poly1305(s2c_key).decrypt(nonce, resp_tag, None)
        except InvalidTag:
            return None

        new_session = SessionKeys(server_session_id, send_key=c2s_key, recv_key=s2c_key)
        self._activate_new_session(new_session)

        self._pending_eph_priv = None
        self._pending_session_id = None
        return new_session

    def _activate_new_session(self, new_session: SessionKeys):
        """Rotates the active session and maintains the previous session during grace period."""
        if self.current_session:
            self.previous_session = self.current_session
        self.current_session = new_session

    # -------------------------------------------------------------------------
    # Data Encapsulation & Decapsulation (Type 3)
    # -------------------------------------------------------------------------
    def encrypt_ip_packet(self, ip_bytes: bytes) -> bytes | None:
        """
        Encapsulates and encrypts a raw Layer 3 IP packet:
          [1B Type=3] [4B SessionID] [8B Nonce Counter] [Encrypted IP Packet + 16B Tag]
        """
        if not self.current_session:
            return None

        session = self.current_session
        counter = session.send_counter
        session.send_counter += 1

        # Construct 12-byte AEAD nonce: 8-byte little-endian counter + 4 zero bytes
        nonce = struct.pack("<Q4x", counter)

        ciphertext = session.send_cipher.encrypt(nonce, ip_bytes, None)

        packet = (
            struct.pack("<BIQ", MSG_DATA, session.session_id, counter) +
            ciphertext
        )
        return packet

    def decrypt_ip_packet(self, raw_packet: bytes) -> bytes | None:
        """
        Decrypts an incoming Type 3 data packet using the active (or grace-period) session key.
        """
        if len(raw_packet) < 1 + 4 + 8 + 16:
            return None

        msg_type, session_id, counter = struct.unpack("<BIQ", raw_packet[:13])
        if msg_type != MSG_DATA:
            return None

        nonce = struct.pack("<Q4x", counter)
        ciphertext = raw_packet[13:]

        # Try current session first
        if self.current_session and self.current_session.session_id == session_id:
            try:
                return self.current_session.recv_cipher.decrypt(nonce, ciphertext, None)
            except InvalidTag:
                return None

        # Fallback to previous session if still within key rotation grace window (15s)
        if (self.previous_session and 
            self.previous_session.session_id == session_id and 
            time.time() - self.current_session.created_at < 15):
            try:
                return self.previous_session.recv_cipher.decrypt(nonce, ciphertext, None)
            except InvalidTag:
                return None

        return None

