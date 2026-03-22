# Identity Network

> **"The network endpoint is a cryptographic identity. IP is only a transient carrier."**

A minimal but real prototype of an identity-native network stack where nodes are addressed
by cryptographic keys, not IP addresses.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                  Application Layer                   │
│          echo / ping / rpc / custom services         │
├─────────────────────────────────────────────────────┤
│               Authorization Layer                    │
│         ACL by NodeId (never by IP)                  │
├─────────────────────────────────────────────────────┤
│            Encrypted Session Layer                   │
│     AES-256-GCM framed messages, nonce counters      │
├─────────────────────────────────────────────────────┤
│           Identity Handshake Layer                   │
│  Ed25519 mutual auth + X25519 ECDH + HKDF-SHA256     │
├─────────────────────────────────────────────────────┤
│             Discovery Layer                          │
│  Signed registration, lookup by NodeId / PubKey      │
├─────────────────────────────────────────────────────┤
│          Transport Layer (carrier only)              │
│    TCP/IP — used as dumb pipe, never as identity     │
└─────────────────────────────────────────────────────┘
```

### Core Primitives

| Concept              | Implementation                          |
|----------------------|-----------------------------------------|
| Node identity        | Ed25519 long-term keypair               |
| NodeId               | SHA-256(public_key) — 32 bytes / 64 hex |
| Human fingerprint    | First 16 hex chars, colon-separated     |
| Session key exchange | X25519 ephemeral ECDH                   |
| Key derivation       | HKDF-SHA256 with direction labels       |
| Encryption           | AES-256-GCM with counter nonces         |
| Discovery auth       | Ed25519 proof-of-ownership signature    |

---

## Protocol Design

### Handshake (5 messages)

```
Client                              Server
  │                                   │
  │── ClientHello ──────────────────► │  eph_pub_c || node_id_c || ts
  │                                   │
  │◄─ ServerHello ─────────────────── │  eph_pub_s || node_id_s || ts
  │◄─ ServerProof ─────────────────── │  pk_s || Ed25519_sig(eph_s||eph_c||node_c||ts)
  │                                   │
  │  [client verifies server identity]│
  │  [if known pubkey: pin check]     │
  │                                   │
  │── ClientProof ──────────────────► │  pk_c || Ed25519_sig(eph_c||eph_s||node_s||ts)
  │                                   │
  │  [server runs ACL check]          │
  │                                   │
  │◄─ SessionAck / AuthReject ──────── │
  │                                   │
  │═══════ Encrypted Session ═════════│
  │  AES-256-GCM, per-direction keys  │
```

**Session key derivation:**
```
dh_secret = X25519(eph_priv_local, eph_pub_remote)
k_i2r = HKDF(dh_secret, salt=eph_i||eph_r, info="idn-v1-init-to-resp-key")
k_r2i = HKDF(dh_secret, salt=eph_i||eph_r, info="idn-v1-resp-to-init-key")
nonce  = base_iv XOR counter (8 bytes, big-endian)
```

### Wire Format

**Handshake frames (plaintext):**
```
[4] magic=0x49444E01  [1] version=0x01  [1] msg_type
[2] flags             [4] payload_len   [...] payload
```

**Encrypted application frames:**
```
[4] magic  [1] version  [1] msg_type  [2] flags
[8] nonce_counter  [4] ct_len  [...] AES-256-GCM(plaintext) + 16-byte tag
AAD = header bytes (integrity without confidentiality)
```

---

## Security Properties

### Guaranteed by the protocol
- **Mutual authentication** — both parties prove Ed25519 private key ownership
- **Forward secrecy** — ephemeral X25519 per session; past sessions safe if long-term key leaks
- **MITM protection** — `connect_by_pubkey()` pins expected server key; mismatch = abort
- **Replay protection** — timestamp freshness check (±30s) on ClientHello; nonce counter monotonicity
- **Identity binding** — session keys derived with both identities in HKDF context
- **GCM authentication** — any ciphertext tampering detected, session terminated
- **ACL enforcement** — access by NodeId, never by IP; IP is never trusted

### Discovery layer
- Registration requires Ed25519 signature over `node_id || endpoint || timestamp`
- Forged registrations rejected — attacker without private key cannot register
- TTL-based expiry (2 min) with heartbeat renewal

### Explicitly NOT covered (prototype scope)
- Traffic analysis / metadata privacy
- Post-quantum cryptography
- Full NAT traversal (STUN/TURN/ICE)
- DoS / amplification hardening
- Global passive adversary
- Certificate transparency / key revocation
- Multi-hop / onion routing
- Tor-style anonymity

---

## Building

```bash
# Dependencies: g++13, libssl.so.3 (OpenSSL 3.x), libcrypto.so.3
# On Ubuntu 22.04+: apt install g++ libssl3 (dev headers via node-headers workaround)

make          # builds all 4 binaries
make tests    # build test suite
make run-tests
```

Produces in `build/`:
- `identitynet-discovery` — discovery server
- `identitynet-server`    — server node
- `identitynet-client`    — client CLI
- `identitynet-tests`     — test suite
- `identitynet-demo`      — in-process full demo

---

## Quick Start

### Step 1 — Discovery server
```bash
./build/identitynet-discovery --port 7700
```

### Step 2 — Server node
```bash
# Generate identity (once)
./build/identitynet-server init --key server.key

# Run server
./build/identitynet-server run \
    --key server.key \
    --port 7701 \
    --discovery 127.0.0.1:7700 \
    --allow-all
```

Output:
```
[server] NodeId: a1b2c3d4...  (64 hex chars)
[server] PubKey: r6Kub85z...  (base64)
[server] Registered with discovery @ 127.0.0.1:7700
[server] Listening on 0.0.0.0:7701
```

### Step 3 — Client (identity-first API, no IP)

```bash
# Generate client identity (once)
./build/identitynet-client init --key client.key

# Connect by NodeId (resolved via discovery — no IP in this call)
./build/identitynet-client ping \
    --key client.key \
    --node a1b2c3d4e5f6...   # 64-char hex NodeId
    --count 4

# Connect by public key (MITM-resistant pinning)
./build/identitynet-client echo \
    --key client.key \
    --pubkey r6Kub85zfI+qfUGx...  # base64 public key
    --message "Hello, Identity Network!"

# Resolve identity in discovery
./build/identitynet-client resolve --node a1b2c3d4...
```

### Step 4 — ACL (access control by identity)

```bash
# Create ACL file (one NodeId hex per line)
echo "a6b15295d48e1590769e3684cf241775ec414ebc85b4e71e955d15e8c9837f89" > acl.txt
echo "# use * for allow-all" >> acl.txt

./build/identitynet-server run \
    --key server.key \
    --acl acl.txt   # only listed NodeIds are accepted
```

---

## CLI Reference

```
identitynet-discovery --port PORT

identitynet-server init  [--key PATH]
identitynet-server run   --key PATH [--port PORT] [--host HOST]
                         [--acl PATH] [--discovery EP] [--allow-all]
                         [--no-register] [--quiet]

identitynet-client init     [--key PATH]
identitynet-client show     [--key PATH]
identitynet-client ping     --node NODEID | --pubkey B64  [--count N]
identitynet-client echo     --node NODEID | --pubkey B64  --message MSG
identitynet-client resolve  --node NODEID | --pubkey B64
identitynet-client stress   --node NODEID  [--count N] [--threads T]
```

---

## Demo Results (verified)

```
SCENARIO 1: connect_by_node_id("e465:c0dd:9ae8:b1f2")
  ✓ Handshake: Ed25519 mutual auth + X25519 ECDH + AES-256-GCM
  ✓ PING  rtt=0.130ms avg (100 sequential)
  ✓ ECHO  recv="[echo] hello identity network [from:a6b1:5295:d48e:1590]"

SCENARIO 2: connect_by_pubkey("r6Kub85zfI+...")  [MITM-resistant]
  ✓ Server key pinned — impostor rejected with "MITM?"

SCENARIO 3: ACL enforcement
  ✓ client1 [a6b1:5295:d48e:1590]: ALLOWED
  ✓ client2 [aa7a:2998:f762:430a]: DENIED (not in ACL)

SCENARIO 4: MITM — wrong pubkey pinned
  ✓ MITM rejected: "Server public key does not match expected! MITM?"

STRESS TEST:
  Sequential  100/100   avg_rtt=0.130ms  throughput=105 conn/s
  Concurrent  200/200   8 threads        throughput=133 conn/s

TEST SUITE: 32/32 PASSED ✓
```

---

## Project Structure

```
identitynet/
├── include/
│   ├── identity.hpp     Ed25519 keypair, NodeId=SHA256(pubkey), sign/verify
│   ├── crypto.hpp       X25519 ECDH, HKDF-SHA256, AES-256-GCM, SessionKeys
│   ├── protocol.hpp     Wire framing, handshake payloads, message types
│   ├── transport.hpp    TCP listener/stream, framed I/O, TransportEndpoint
│   ├── handshake.hpp    Mutual auth state machine (initiator + responder)
│   ├── session.hpp      Encrypted session: AES-256-GCM frames, nonce counter
│   ├── keystore.hpp     Save/load Ed25519 identity to/from disk
│   ├── discovery.hpp    Discovery server + client (signed registration/lookup)
│   ├── authz.hpp        ACL policy: allowlist/deny by NodeId
│   ├── server.hpp       IdentityServer with ACL, service dispatch, heartbeat
│   └── client.hpp       IdentityClient: connect_by_node_id / connect_by_pubkey
├── src/
│   ├── main_discovery.cpp
│   ├── main_server.cpp
│   └── main_client.cpp
├── tests/
│   ├── tests.cpp        32 unit + integration tests
│   └── demo.cpp         In-process 4-scenario demo + stress test
└── Makefile
```

---

## Threat Model

| Threat                        | Mitigation                                      |
|-------------------------------|-------------------------------------------------|
| Impersonation                 | Ed25519 identity proof in every handshake       |
| MITM on known server          | `connect_by_pubkey()` pins expected key         |
| Replay of handshake           | Timestamp ±30s + monotonic nonce counter        |
| Forged discovery registration | Signature over node_id\|endpoint\|timestamp    |
| IP spoofing                   | IP never trusted — identity is the only address |
| ACL bypass                    | ACL checked after cryptographic identity proof  |
| Session tampering             | AES-256-GCM authentication tag on every frame   |

---

## Roadmap

1. **NAT traversal** — STUN/TURN/ICE, UDP hole punching, relay nodes
2. **DHT discovery** — replace centralized discovery with Kademlia or S/Kademlia
3. **QUIC transport** — replace TCP with QUIC for multiplexing + 0-RTT
4. **Multi-hop routing** — overlay paths: A→relay→B when direct unreachable
5. **Capability tokens** — signed delegated access tokens per service/action
6. **Gossip peer discovery** — passive peer exchange, no central bootstrap
7. **Stream multiplexing** — multiple application streams per session (QUIC streams)
8. **Post-quantum** — hybrid X25519+ML-KEM key exchange
9. **Privacy mode** — anonymous connections, traffic padding, timing obfuscation
10. **Service mesh policies** — rate limiting, per-service ACLs, audit log


---

## Demo results

```
PS D:\source\personal\identitynet> .\run.bat demo
[*] Running full Identity Network demo...
[*] Demonstrates all 4 scenarios:
    1. connect_by_node_id  (discovery resolution)
    2. connect_by_pubkey   (MITM-resistant pinning)
    3. ACL enforcement     (allow + deny)
    4. MITM rejection      (wrong pubkey pinned)

╔══════════════════════════════════════════════════════╗
║         Identity Network — Live Demo                 ║
║  "Identity IS the address. IP is only a carrier."    ║
╚══════════════════════════════════════════════════════╝

▶  Starting discovery server on :17900
[discovery] Server started on 0.0.0.0:17900
▶  Starting identity server on :17901
[server] Identity: NodeId(8269:cdb4:cad2:3c9f)  PubKey(DYrrzwBwUDUZGaHZ...)
[server] NodeId:   8269cdb4cad23c9fd2f28702e6abc633b766e1e520823f0ae7d960aa43becbf4
[server] PubKey:   DYrrzwBwUDUZGaHZf6RYx2btkgkVoj/aqg33RdUOBHw=
[discovery] Registered: 8269:cdb4:cad2:3c9f @ 127.0.0.1:17901
[server] Registered with discovery @ 127.0.0.1:17900
[server] Listening on 0.0.0.0:17901
[server] ACL: open (allow all authenticated peers)

══════════════════════════════════════════════════════
SERVER IDENTITY (long-term Ed25519 key):
  NodeId  : 8269cdb4cad23c9fd2f28702e6abc633b766e1e520823f0ae7d960aa43becbf4
  Finger  : 8269:cdb4:cad2:3c9f
  PubKey  : DYrrzwBwUDUZGaHZf6RYx2btkgkVoj/aqg33RdUOBHw=
══════════════════════════════════════════════════════

CLIENT IDENTITY (long-term Ed25519 key):
  NodeId  : bd9d8e14dd646889982d980b0da940ed7bd28501ff07d719f9f40c7686e16b87
  Finger  : bd9d:8e14:dd64:6889
══════════════════════════════════════════════════════

┌──────────────────────────────────────────────────────┐
│ SCENARIO 1: client.connect_by_node_id(node_id)       │
│  No IP address visible in this call.                 │
└──────────────────────────────────────────────────────┘
  Calling: connect_by_node_id("8269:cdb4:cad2:3c9f")
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
  ✓ Handshake complete
  ✓ Peer identity authenticated: 8269:cdb4:cad2:3c9f
  ✓ Ed25519 mutual auth + X25519 ECDH + AES-256-GCM session
  ✓ PING  rtt=0.000 ms
  ✓ ECHO  sent="hello identity network"
  ✓ ECHO  recv="[echo] hello identity network [from:bd9d:8e14:dd64:6889]"
  ✓ Session closed (sent=122 recv=156 bytes)
[server] Session ended: bd9d:8e14:dd64:6889 | sent=156 recv=122 bytes

┌──────────────────────────────────────────────────────┐
│ SCENARIO 2: client.connect_by_pubkey(pubkey)         │
│  Server key is pinned — any impostor is rejected.    │
└──────────────────────────────────────────────────────┘
  Calling: connect_by_pubkey("DYrrzwBwUDUZGaHZf6RYx2btkgkV...")
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
  ✓ Server key matches pinned pubkey — no MITM
  ✓ Peer: 8269:cdb4:cad2:3c9f
  ✓ ECHO  recv="[echo] pubkey-pinned connection works! [from:bd9d:8e14:dd64:6889]"

┌──────────────────────────────────────────────────────┐
│ SCENARIO 3: ACL — identity-based access control      │
│  Server allowlist contains only client1.node_id.     │
│  client2 (different identity) must be denied.        │
└─────────────────────[server] Handshake failed from carrier 127.0.0.1:35212: No ClientProof received
─────────────────────────────────┘
[server] Session ended: bd9d:8e14:dd64:6889 | sent=113 recv=79 bytes
[server] Identity: NodeId(e419:1b2d:97d2:3294)  PubKey(oS3pR40/u19RA+le...)
[server] NodeId:   e4191b2d97d2329410b0be700e1fed62bad2bd014c4026104872842944594d1c
[server] PubKey:   oS3pR40/u19RA+leFbYH6kgOXSh9Do5Z4KyRGCKeQHQ=
[discovery] Registered: e419:1b2d:97d2:3294 @ 127.0.0.1:17902
[server] Registered with discovery @ 127.0.0.1:17900
[server] Listening on 0.0.0.0:17902
[server] ACL: allowlist (1 peers)
  ACL allowlist: [bd9d:8e14:dd64:6889]

[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
  ✓ client1 [bd9d:8e14:dd64:6889]: ALLOWED (rtt=0.00ms)
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL DENY: c85c4c1b40eba9dfa79fc05f47f306534be5ef9eebf2dd6b4875625677f91e57
  ✓ client2 [c85c:4c1b:40eb:a9df]: DENIED (not in ACL)

┌──────────────────────────────────────────────────────┐
│ SCENARIO 4: MITM rejected — wrong pubkey pinned      │
│  Client pins an impostor key → handshake aborts.     │
└──────────────────────────────────────────────────────┘
  Impostor pubkey: G9C3Ntj/PWZSeUHe6v6s...
  Real server key: DYrrzwBwUDUZGaHZf6RY...
  ✓ MITM rejected: Server public key does not match expected! MITM?

┌──────────────────────────────────────────────────────┐
│ STRESS TEST: concurrent identity-based connections   │
└──────────────────────────────────────────────────────┘
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
  Sequential  100/100  avg_rtt=0.090ms  throughput=1471 conn/s  total=68ms
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
[server] ACL ALLOW: bd9d:8e14:dd64:6889
[server] Secure session established with bd9d:8e14:dd64:6889
[server] Session ended: bd9d:8e14:dd64:6889 | sent=52 recv=52 bytes
  Concurrent  200/200  8 threads  avg_rtt=0.060ms  throughput=8000 conn/s  total=25ms

══════════════════════════════════════════════════════
DEMO RESULTS: 4/4 scenarios passed
ALL SCENARIOS PASSED ✓
══════════════════════════════════════════════════════|
```