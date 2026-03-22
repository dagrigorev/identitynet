#pragma once
// ============================================================================
// proxy_proto.hpp — Proxy tunnel wire payloads
//
// Stream multiplexing: each TCP connection through the SOCKS5 proxy
// gets a unique stream_id (uint32). All proxy messages carry stream_id
// so one IdentityNet session can carry many browser TCP connections.
//
// Flow:
//   Browser → SOCKS5(local) → PROXY_CONNECT → IdentityNet → VPS
//   VPS connects to real host, sends PROXY_CONNECTED
//   Browser ↔ PROXY_DATA ↔ VPS ↔ real host (bidirectional stream)
//   Either side sends PROXY_CLOSE to tear down
// ============================================================================

#include "protocol.hpp"
#include <string>
#include <vector>
#include <cstring>

namespace idn::proxy {

// ---------------------------------------------------------------------------
// PROXY_CONNECT: client asks server to open TCP connection to host:port
// stream_id(4) || host_len(2) || host(...) || port(2)
// ---------------------------------------------------------------------------
struct ConnectPayload {
    uint32_t    stream_id = 0;
    std::string host;
    uint16_t    port      = 0;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(4 + 2 + host.size() + 2);
        proto::write_u32_be(v.data(),     stream_id);
        proto::write_u16_be(v.data()+4,   (uint16_t)host.size());
        memcpy(v.data()+6, host.data(), host.size());
        proto::write_u16_be(v.data()+6+host.size(), port);
        return v;
    }

    static ConnectPayload deserialize(const uint8_t* p, size_t len) {
        if (len < 8) throw std::runtime_error("ConnectPayload too short");
        ConnectPayload c;
        c.stream_id = proto::read_u32_be(p);
        uint16_t hlen = proto::read_u16_be(p+4);
        if (len < 6u + hlen + 2u) throw std::runtime_error("ConnectPayload truncated");
        c.host.assign((const char*)p+6, hlen);
        c.port = proto::read_u16_be(p+6+hlen);
        return c;
    }
};

// ---------------------------------------------------------------------------
// PROXY_CONNECTED: server confirms connection opened
// stream_id(4)
// ---------------------------------------------------------------------------
struct ConnectedPayload {
    uint32_t stream_id = 0;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(4);
        proto::write_u32_be(v.data(), stream_id);
        return v;
    }
    static ConnectedPayload deserialize(const uint8_t* p, size_t len) {
        if (len < 4) throw std::runtime_error("ConnectedPayload too short");
        return { proto::read_u32_be(p) };
    }
};

// ---------------------------------------------------------------------------
// PROXY_DATA: raw TCP bytes for a stream
// stream_id(4) || data_len(4) || data(...)
// ---------------------------------------------------------------------------
struct DataPayload {
    uint32_t             stream_id = 0;
    std::vector<uint8_t> data;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(8 + data.size());
        proto::write_u32_be(v.data(),   stream_id);
        proto::write_u32_be(v.data()+4, (uint32_t)data.size());
        if (!data.empty()) memcpy(v.data()+8, data.data(), data.size());
        return v;
    }
    static DataPayload deserialize(const uint8_t* p, size_t len) {
        if (len < 8) throw std::runtime_error("DataPayload too short");
        DataPayload d;
        d.stream_id = proto::read_u32_be(p);
        uint32_t dlen = proto::read_u32_be(p+4);
        if (len < 8u + dlen) throw std::runtime_error("DataPayload truncated");
        d.data.assign(p+8, p+8+dlen);
        return d;
    }
};

// ---------------------------------------------------------------------------
// PROXY_CLOSE: either side closes a stream
// stream_id(4)
// ---------------------------------------------------------------------------
struct ClosePayload {
    uint32_t stream_id = 0;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(4);
        proto::write_u32_be(v.data(), stream_id);
        return v;
    }
    static ClosePayload deserialize(const uint8_t* p, size_t len) {
        if (len < 4) throw std::runtime_error("ClosePayload too short");
        return { proto::read_u32_be(p) };
    }
};

// ---------------------------------------------------------------------------
// PROXY_ERROR: server failed to connect
// stream_id(4) || msg_len(4) || msg(...)
// ---------------------------------------------------------------------------
struct ErrorPayload {
    uint32_t    stream_id = 0;
    std::string message;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> v(8 + message.size());
        proto::write_u32_be(v.data(),   stream_id);
        proto::write_u32_be(v.data()+4, (uint32_t)message.size());
        memcpy(v.data()+8, message.data(), message.size());
        return v;
    }
    static ErrorPayload deserialize(const uint8_t* p, size_t len) {
        if (len < 8) throw std::runtime_error("ErrorPayload too short");
        ErrorPayload e;
        e.stream_id = proto::read_u32_be(p);
        uint32_t mlen = proto::read_u32_be(p+4);
        if (len >= 8u + mlen) e.message.assign((const char*)p+8, mlen);
        return e;
    }
};

} // namespace idn::proxy
