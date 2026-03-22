#pragma once
// ============================================================================
// protocol.hpp — Identity Network wire protocol
//
// Framing: Every message on the wire is:
//   [4 bytes: magic] [1 byte: version] [1 byte: msg_type]
//   [2 bytes: flags] [4 bytes: payload_length] [payload...]
//
// Handshake phases (identity-first, not IP-first):
//   1. ClientHello  → ephemeral X25519 pubkey + client node_id + timestamp
//   2. ServerHello  → ephemeral X25519 pubkey + server node_id + timestamp
//   3. ClientProof  → Ed25519 sig(client_eph_pub || server_eph_pub || timestamp)
//   4. ServerProof  → Ed25519 sig(server_eph_pub || client_eph_pub || timestamp)
//   5. SessionEstablished — both sides derive SessionKeys via HKDF
//   6. Encrypted application frames
// ============================================================================

#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include "identity.hpp"

namespace idn::proto {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static constexpr uint32_t MAGIC   = 0x49444E01;  // "IDN\x01"
static constexpr uint8_t  VERSION = 0x01;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------
enum class MsgType : uint8_t {
    // Handshake
    CLIENT_HELLO      = 0x01,
    SERVER_HELLO      = 0x02,
    CLIENT_PROOF      = 0x03,
    SERVER_PROOF      = 0x04,
    SESSION_ACK       = 0x05,
    AUTH_REJECT       = 0x06,

    // Discovery control plane (JSON payload, not encrypted)
    DISC_REGISTER     = 0x10,
    DISC_REGISTER_ACK = 0x11,
    DISC_LOOKUP       = 0x12,
    DISC_LOOKUP_RESP  = 0x13,
    DISC_HEARTBEAT    = 0x14,
    DISC_HEARTBEAT_ACK= 0x15,

    // Application (encrypted, after session established)
    PING              = 0x20,
    PONG              = 0x21,
    ECHO_REQ          = 0x22,
    ECHO_RESP         = 0x23,
    APP_DATA          = 0x24,
    APP_DATA_ACK      = 0x25,

    // Proxy tunnel messages (encrypted, multiplexed streams)
    PROXY_CONNECT     = 0x30,
    PROXY_CONNECTED   = 0x31,
    PROXY_DATA        = 0x32,
    PROXY_CLOSE       = 0x33,
    PROXY_ERROR       = 0x34,

    // Error / control
    ERROR             = 0xF0,
    GOODBYE           = 0xFF,
};

// Error codes
enum class ErrorCode : uint16_t {
    OK               = 0,
    AUTH_FAILED      = 1,
    ACCESS_DENIED    = 2,
    UNKNOWN_NODE     = 3,
    PROTOCOL_ERROR   = 4,
    INTERNAL         = 5,
    REPLAY_DETECTED  = 6,
    TIMEOUT          = 7,
};

// ---------------------------------------------------------------------------
// Wire header: 12 bytes fixed
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct WireHeader {
    uint32_t magic;
    uint8_t  version;
    uint8_t  msg_type;
    uint16_t flags;
    uint32_t payload_len;
};
#pragma pack(pop)

static_assert(sizeof(WireHeader) == 12, "WireHeader must be 12 bytes");

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------
inline void write_u16_be(uint8_t* p, uint16_t v) {
    p[0] = (v >> 8) & 0xFF; p[1] = v & 0xFF;
}
inline void write_u32_be(uint8_t* p, uint32_t v) {
    p[0]=(v>>24)&0xFF; p[1]=(v>>16)&0xFF; p[2]=(v>>8)&0xFF; p[3]=v&0xFF;
}
inline void write_u64_be(uint8_t* p, uint64_t v) {
    for (int i=7;i>=0;--i) { p[7-i] = (v >> (i*8)) & 0xFF; }
}
inline uint16_t read_u16_be(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | p[1];
}
inline uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
inline uint64_t read_u64_be(const uint8_t* p) {
    uint64_t v = 0;
    for (int i=0;i<8;++i) v = (v << 8) | p[i];
    return v;
}

// Build a framed message
inline std::vector<uint8_t> frame(MsgType type, const std::vector<uint8_t>& payload,
                                   uint16_t flags = 0) {
    std::vector<uint8_t> msg(sizeof(WireHeader) + payload.size());
    WireHeader* hdr = reinterpret_cast<WireHeader*>(msg.data());
    write_u32_be(reinterpret_cast<uint8_t*>(&hdr->magic), MAGIC);
    hdr->version   = VERSION;
    hdr->msg_type  = static_cast<uint8_t>(type);
    write_u16_be(reinterpret_cast<uint8_t*>(&hdr->flags), flags);
    write_u32_be(reinterpret_cast<uint8_t*>(&hdr->payload_len),
                 (uint32_t)payload.size());
    if (!payload.empty())
        memcpy(msg.data() + sizeof(WireHeader), payload.data(), payload.size());
    return msg;
}

inline std::vector<uint8_t> frame(MsgType type, uint16_t flags = 0) {
    return frame(type, {}, flags);
}

// ---------------------------------------------------------------------------
// Handshake payloads
// ---------------------------------------------------------------------------

// ClientHello payload: ephemeral_pub(32) || node_id(32) || timestamp_ms(8)
struct ClientHelloPayload {
    std::array<uint8_t, 32> eph_pub{};
    NodeId                  node_id{};
    uint64_t                timestamp_ms = 0;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(72);
        memcpy(v.data(),    eph_pub.data(),       32);
        memcpy(v.data()+32, node_id.bytes.data(), 32);
        write_u64_be(v.data()+64, timestamp_ms);
        return v;
    }

    static ClientHelloPayload deserialize(const uint8_t* p, size_t len) {
        if (len < 72) throw std::runtime_error("ClientHello too short");
        ClientHelloPayload h;
        memcpy(h.eph_pub.data(),       p,    32);
        memcpy(h.node_id.bytes.data(), p+32, 32);
        h.timestamp_ms = read_u64_be(p+64);
        return h;
    }
};

// ServerHello payload: ephemeral_pub(32) || node_id(32) || timestamp_ms(8)
struct ServerHelloPayload {
    std::array<uint8_t, 32> eph_pub{};
    NodeId                  node_id{};
    uint64_t                timestamp_ms = 0;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(72);
        memcpy(v.data(),    eph_pub.data(),       32);
        memcpy(v.data()+32, node_id.bytes.data(), 32);
        write_u64_be(v.data()+64, timestamp_ms);
        return v;
    }

    static ServerHelloPayload deserialize(const uint8_t* p, size_t len) {
        if (len < 72) throw std::runtime_error("ServerHello too short");
        ServerHelloPayload h;
        memcpy(h.eph_pub.data(),       p,    32);
        memcpy(h.node_id.bytes.data(), p+32, 32);
        h.timestamp_ms = read_u64_be(p+64);
        return h;
    }
};

// ClientProof payload: public_key(32) || signature(64)
// sig covers: client_eph_pub || server_eph_pub || server_node_id || timestamp_ms
struct ClientProofPayload {
    PublicKey              public_key{};
    std::array<uint8_t,64> signature{};

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(96);
        memcpy(v.data(),    public_key.bytes.data(), 32);
        memcpy(v.data()+32, signature.data(),        64);
        return v;
    }

    static ClientProofPayload deserialize(const uint8_t* p, size_t len) {
        if (len < 96) throw std::runtime_error("ClientProof too short");
        ClientProofPayload c;
        memcpy(c.public_key.bytes.data(), p,    32);
        memcpy(c.signature.data(),        p+32, 64);
        return c;
    }
};

// ServerProof payload: public_key(32) || signature(64)
// sig covers: server_eph_pub || client_eph_pub || client_node_id || timestamp_ms
struct ServerProofPayload {
    PublicKey              public_key{};
    std::array<uint8_t,64> signature{};

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(96);
        memcpy(v.data(),    public_key.bytes.data(), 32);
        memcpy(v.data()+32, signature.data(),        64);
        return v;
    }

    static ServerProofPayload deserialize(const uint8_t* p, size_t len) {
        if (len < 96) throw std::runtime_error("ServerProof too short");
        ServerProofPayload s;
        memcpy(s.public_key.bytes.data(), p,    32);
        memcpy(s.signature.data(),        p+32, 64);
        return s;
    }
};

// Helper: build the "transcript" to sign for client proof
inline std::vector<uint8_t> client_proof_transcript(
    const std::array<uint8_t,32>& client_eph,
    const std::array<uint8_t,32>& server_eph,
    const NodeId& server_node_id,
    uint64_t timestamp_ms)
{
    std::vector<uint8_t> t(104);
    memcpy(t.data(),    client_eph.data(),            32);
    memcpy(t.data()+32, server_eph.data(),            32);
    memcpy(t.data()+64, server_node_id.bytes.data(),  32);
    write_u64_be(t.data()+96, timestamp_ms);
    return t;
}

inline std::vector<uint8_t> server_proof_transcript(
    const std::array<uint8_t,32>& server_eph,
    const std::array<uint8_t,32>& client_eph,
    const NodeId& client_node_id,
    uint64_t timestamp_ms)
{
    std::vector<uint8_t> t(104);
    memcpy(t.data(),    server_eph.data(),            32);
    memcpy(t.data()+32, client_eph.data(),            32);
    memcpy(t.data()+64, client_node_id.bytes.data(),  32);
    write_u64_be(t.data()+96, timestamp_ms);
    return t;
}

// ---------------------------------------------------------------------------
// Application-layer payload helpers
// ---------------------------------------------------------------------------

// PingPong: request_id(8) || timestamp_ms(8)
struct PingPayload {
    uint64_t request_id  = 0;
    uint64_t timestamp_ms= 0;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(16);
        write_u64_be(v.data(),   request_id);
        write_u64_be(v.data()+8, timestamp_ms);
        return v;
    }
    static PingPayload deserialize(const uint8_t* p, size_t len) {
        if (len < 16) throw std::runtime_error("Ping too short");
        PingPayload pp;
        pp.request_id   = read_u64_be(p);
        pp.timestamp_ms = read_u64_be(p+8);
        return pp;
    }
};

// Echo: request_id(8) || message_len(4) || message(...)
struct EchoPayload {
    uint64_t    request_id = 0;
    std::string message;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(12 + message.size());
        write_u64_be(v.data(),   request_id);
        write_u32_be(v.data()+8, (uint32_t)message.size());
        memcpy(v.data()+12, message.data(), message.size());
        return v;
    }
    static EchoPayload deserialize(const uint8_t* p, size_t len) {
        if (len < 12) throw std::runtime_error("Echo too short");
        EchoPayload e;
        e.request_id = read_u64_be(p);
        uint32_t mlen = read_u32_be(p+8);
        if (len < 12 + mlen) throw std::runtime_error("Echo truncated");
        e.message.assign((const char*)p+12, mlen);
        return e;
    }
};

// Error: error_code(2) || message_len(4) || message(...)
struct ErrorPayload {
    ErrorCode   code    = ErrorCode::OK;
    std::string message;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(6 + message.size());
        write_u16_be(v.data(),   (uint16_t)code);
        write_u32_be(v.data()+2, (uint32_t)message.size());
        memcpy(v.data()+6, message.data(), message.size());
        return v;
    }
    static ErrorPayload deserialize(const uint8_t* p, size_t len) {
        if (len < 6) throw std::runtime_error("Error payload too short");
        ErrorPayload e;
        e.code = (ErrorCode)read_u16_be(p);
        uint32_t mlen = read_u32_be(p+2);
        if (len >= 6 + mlen) e.message.assign((const char*)p+6, mlen);
        return e;
    }
};

} // namespace idn::proto
