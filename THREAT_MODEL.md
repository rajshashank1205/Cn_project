# BACSE203 Project 22: Threat Model & Security Boundary

**Project Title:** VPN / Secure Tunnel Application (Mini-WireGuard)  
**Course Outcomes:** CO3 (Network Layer & Routing Protocols), CO5 (Network Security & Applied Cryptography)  
**Deliverable:** Expected Deliverable #5 & Milestone 88 Report  

---

## 1. System Overview & Security Boundary

Mini-WireGuard establishes an encrypted, authenticated Layer-3 point-to-point tunnel between two untrusted network endpoints (Client and Server) operating over an adversarial intermediate network (e.g., public Wi-Fi, the public Internet).

```
+---------------------------------------------------------------------------------------+
|                                    TRUST BOUNDARY                                     |
|                                                                                       |
|  [ Client OS Network Stack ]                               [ Server OS Network Stack] |
|            ▲                                                             ▲            |
|            │ (Plain L3 IP Packets)                                       │            |
|            ▼                                                             ▼            |
|   [ Wintun Virtual TUN ]                                       [ Wintun Virtual TUN ] |
|            ▲                                                             ▲            |
|            │ (Local Inter-process)                                       │            |
|            ▼                                                             ▼            |
|    [ client.py Core ]                                            [ server.py Core ]   |
|            ▲                                                             ▲            |
+------------┼─────────────────────────────────────────────────────────────┼------------+
             │                                                             │
             ▼                                                             ▼
     [ UDP Port 51820 ] ◄══════════════════════════════════════════► [ UDP Port 51820 ]
                                 ADVERSARIAL NETWORK
                         (Wi-Fi / ISP / Attacker Controlled)
```

---

## 2. Threat Model & Attacker Capabilities

We evaluate Mini-WireGuard under the canonical **Dolev-Yao Network Attacker Model**. The adversary possesses complete control over the network medium between the client and server.

### 2.1 Adversary Capabilities
The network attacker can:
1. **Eavesdrop:** Intercept and record all UDP datagrams transmitted between Client and Server.
2. **Modify / Tamper:** Flip arbitrary bits, alter headers, or inject payload corruptions in transit.
3. **Replay:** Record previously transmitted valid packets and retransmit them at a later time.
4. **Inject:** Forge arbitrary UDP datagrams with spoofed IP addresses and port numbers.
5. **Drop / Delay:** Selectively drop packets or induce artificial latency.

### 2.2 Adversary Limitations (Out of Scope)
The adversary **cannot**:
- Compromise the host operating system, memory space, or file system of either endpoint (Host OS security is trusted).
- Break the underlying cryptographic hardness assumptions of Curve25519 (Computational Diffie-Hellman problem) or ChaCha20-Poly1305.

---

## 3. Cryptographic Primitives & Security Objectives

| Security Property | Cryptographic Mechanism | Implementation in Mini-WireGuard |
| :--- | :--- | :--- |
| **Confidentiality** | ChaCha20 Stream Cipher (256-bit key) | Raw IP packets are encrypted before UDP transmission. |
| **Authenticity & Integrity** | Poly1305 Message Authentication Code (128-bit MAC tag) | Any bit flip in transit causes `InvalidTag` exception; packet dropped. |
| **Key Agreement** | Ephemeral Diffie-Hellman over Curve25519 (X25519) | Noise-IK inspired handshake derives dynamic session keys. |
| **Key Derivation** | HKDF-SHA256 (RFC 5869) | Derives independent bidirectional keys (`c2s_key`, `s2c_key`). |
| **Replay Protection** | 64-bit Monotonic Sequence Counter + Handshake Timestamp | Handshake rejects timestamps older than 120s; data packets use strict sequential nonces. |
| **Perfect Forward Secrecy (PFS)** | Periodic Ephemeral Key Rotation | Ephemeral session keys are regenerated every 60 seconds and destroyed. |

---

## 4. Key Rotation & Perfect Forward Secrecy (PFS)

### 4.1 The Need for Key Rotation
In symmetric stream ciphers like ChaCha20, **nonce reuse under the same key is catastrophic**, compromising confidentiality. Furthermore, if a long-lived session key were ever compromised, an attacker who recorded historical traffic could retroactively decrypt the entire communication stream.

### 4.2 Mini-WireGuard Rekeying State Machine
1. **Periodic Trigger:** Every $N$ seconds (default: 60s) or after $M$ packets, the client initiates a rekey event.
2. **Fresh Ephemeral Pair:** The client and server generate brand new X25519 ephemeral keypairs $(e_{c}, e_{s})$.
3. **Triple Diffie-Hellman:** A fresh shared secret is computed:
   $$SS = \text{X25519}(e_s, e_c) \parallel \text{X25519}(s_s, e_c) \parallel \text{X25519}(e_s, s_c)$$
4. **Grace Window:** During key transition, the previous session key is preserved for 15 seconds to allow in-flight packets to be decrypted without packet loss.
5. **Memory Erasure:** Old session keys are dereferenced and garbage collected, guaranteeing that historical traffic cannot be decrypted even if future session keys are compromised.

---

## 5. Explicit Assumptions

1. **Pre-Shared Static Identity Trust:** Prior to initiating communication, the client is configured with the server's authentic static public key, and the server is configured with the client's authentic static public key (Trust On First Configuration / Pinning).
2. **System Clock Coarse Synchronization:** Client and Server clocks are synchronized within 120 seconds for the initial timestamp anti-replay verification.
3. **Entropy Source:** The OS Cryptographic Random Number Generator (`os.urandom` / Windows CryptGenRandom) generates cryptographically secure, unpredictable nonces and ephemeral private keys.

---

## 6. Known Limitations & Residual Risks

1. **Traffic Analysis & Metadata Leakage:**
   - *Limitation:* While packet payloads are encrypted, packet timing, transmission frequency, and ciphertext size are observable by a passive network monitor.
   - *Mitigation:* In full-scale WireGuard, fixed MTU padding can obscure packet sizes.
2. **Denial-of-Service (DoS) via UDP Flooding:**
   - *Limitation:* An unauthenticated attacker can flood UDP port 51820 with dummy Handshake Initiation packets, consuming CPU cycles on X25519 scalar multiplications.
   - *Mitigation:* Production WireGuard uses Cookie Reply packets (based on SipHash-2-4) under high load.
3. **Post-Quantum Security:**
   - *Limitation:* Curve25519 is vulnerable to Shor's algorithm running on large-scale quantum computers.
   - *Mitigation:* Mini-WireGuard can incorporate post-quantum pre-shared symmetric keys (Noise_IKpsk2).

---

## 7. Viva Defense & Conclusion

Mini-WireGuard implements a sound Layer-3 secure tunneling architecture satisfying all security goals demanded by **Project 22**:
- Mutual authentication guarantees that only authorized static key owners can join the tunnel.
- ChaCha20-Poly1305 guarantees that tampering at the network layer is mathematically impossible without detection.
- Dynamic X25519 key rotation limits the cryptanalytic window of exposure and guarantees forward secrecy.

