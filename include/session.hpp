#pragma once
// ============================================================================
// session.hpp — Encrypted session layer
//
// After handshake, all application data is wrapped in EncryptedFrame:
//   [4 bytes: magic] [1 byte: version] [1 byte: msg_type]
//   [2 bytes: flags] [8 bytes: nonce_counter] [4 bytes: ct_len]
//   [ct_len bytes: AES-256-GCM(plaintext)] [16 bytes: GCM tag embedded in ct]
//
// AAD (additional authenticated data) = header bytes 0..19 (everything before ct)
// This ensures header integrity without encrypting it.
// ============================================================================

#include "crypto.hpp"
#include "transport.hpp"
#include "protocol.hpp"
#include <atomic>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <functional>

namespace idn {

// ---------------------------------------------------------------------------
// EncryptedFrame wire layout constants
// ---------------------------------------------------------------------------
static constexpr size_t ENC_HEADER_SIZE = 20; // magic(4)+ver(1)+type(1)+flags(2)+nonce(8)+ct_len(4)
static constexpr size_t GCM_TAG_SIZE    = 16;

struct EncFrameHeader {
    uint32_t magic;
    uint8_t  version;
    uint8_t  msg_type;
    uint16_t flags;
    uint64_t nonce_counter;
    uint32_t ct_len; // ciphertext + tag
};

inline std::vector<uint8_t> serialize_enc_header(const EncFrameHeader& h) {
    std::vector<uint8_t> v(ENC_HEADER_SIZE);
    proto::write_u32_be(v.data(),    h.magic);
    v[4] = h.version;
    v[5] = h.msg_type;
    proto::write_u16_be(v.data()+6,  h.flags);
    proto::write_u64_be(v.data()+8,  h.nonce_counter);
    proto::write_u32_be(v.data()+16, h.ct_len);
    return v;
}

inline EncFrameHeader parse_enc_header(const uint8_t* p) {
    EncFrameHeader h;
    h.magic         = proto::read_u32_be(p);
    h.version       = p[4];
    h.msg_type      = p[5];
    h.flags         = proto::read_u16_be(p+6);
    h.nonce_counter = proto::read_u64_be(p+8);
    h.ct_len        = proto::read_u32_be(p+16);
    return h;
}

// ---------------------------------------------------------------------------
// SecureSession: bidirectional encrypted channel bound to a peer identity
// ---------------------------------------------------------------------------
class SecureSession {
public:
    SecureSession(TcpStream stream,
                  HandshakeResult handshake_result)
        : stream_(std::move(stream)),
          peer_node_id_(handshake_result.peer_node_id),
          peer_public_key_(handshake_result.peer_public_key),
          keys_(handshake_result.session_keys),
          established_at_ms_(handshake_result.established_at_ms) {}

    SecureSession(SecureSession&&) = default;
    SecureSession(const SecureSession&) = delete;

    // -----------------------------------------------------------------------
    // Public identity accessors
    // -----------------------------------------------------------------------
    const NodeId&    peer_node_id()    const { return peer_node_id_; }
    const PublicKey& peer_public_key() const { return peer_public_key_; }
    uint64_t         established_at()  const { return established_at_ms_; }
    bool             is_closed()       const { return closed_.load(); }

    // -----------------------------------------------------------------------
    // Send an encrypted application message
    // -----------------------------------------------------------------------
    bool send(proto::MsgType type, const std::vector<uint8_t>& plaintext,
              uint16_t flags = 0) {
        if (closed_) return false;

        std::lock_guard<std::mutex> lk(send_mu_);

        uint64_t counter = keys_.send_nonce++;
        auto nonce = SessionKeys::make_nonce(keys_.send_iv, counter);

        // Build header for AAD
        EncFrameHeader hdr;
        hdr.magic         = proto::MAGIC;
        hdr.version       = proto::VERSION;
        hdr.msg_type      = (uint8_t)type;
        hdr.flags         = flags;
        hdr.nonce_counter = counter;
        hdr.ct_len        = (uint32_t)(plaintext.size() + GCM_TAG_SIZE);

        auto hdr_bytes = serialize_enc_header(hdr);

        // Encrypt: plaintext → ciphertext || tag
        auto ct = AESGCM::encrypt(
            keys_.send_key.data(), nonce.data(),
            plaintext.data(), plaintext.size(),
            hdr_bytes.data(), hdr_bytes.size());

        // Wire: header || ciphertext+tag
        std::vector<uint8_t> wire;
        wire.reserve(ENC_HEADER_SIZE + ct.size());
        wire.insert(wire.end(), hdr_bytes.begin(), hdr_bytes.end());
        wire.insert(wire.end(), ct.begin(), ct.end());

        if (!stream_.send_all(wire)) {
            closed_ = true;
            return false;
        }
        bytes_sent_ += wire.size();
        msgs_sent_++;
        return true;
    }

    bool send(proto::MsgType type, uint16_t flags = 0) {
        return send(type, {}, flags);
    }

    // -----------------------------------------------------------------------
    // Receive and decrypt one application message
    // -----------------------------------------------------------------------
    struct ReceivedMessage {
        proto::MsgType          type;
        uint16_t                flags;
        std::vector<uint8_t>    payload;
        uint64_t                nonce_counter;
    };

    std::optional<ReceivedMessage> recv(int timeout_ms = 30000) {
        if (closed_) return std::nullopt;

        // Read encrypted header
        uint8_t hdr_buf[ENC_HEADER_SIZE];
        if (!stream_.recv_exact(hdr_buf, ENC_HEADER_SIZE, timeout_ms)) {
            closed_ = true;
            return std::nullopt;
        }

        auto hdr = parse_enc_header(hdr_buf);

        if (hdr.magic != proto::MAGIC || hdr.version != proto::VERSION) {
            closed_ = true;
            return std::nullopt;
        }

        if (hdr.ct_len < GCM_TAG_SIZE || hdr.ct_len > 16*1024*1024) {
            closed_ = true;
            return std::nullopt;
        }

        // Replay protection: nonce must be strictly increasing
        if (hdr.nonce_counter <= last_recv_nonce_ && last_recv_nonce_ != 0) {
            closed_ = true;
            return std::nullopt; // replay or reorder attack
        }

        // Read ciphertext+tag
        std::vector<uint8_t> ct(hdr.ct_len);
        if (!stream_.recv_exact(ct.data(), hdr.ct_len, timeout_ms)) {
            closed_ = true;
            return std::nullopt;
        }

        // Decrypt
        auto nonce = SessionKeys::make_nonce(keys_.recv_iv, hdr.nonce_counter);
        auto pt = AESGCM::decrypt(
            keys_.recv_key.data(), nonce.data(),
            ct.data(), ct.size(),
            hdr_buf, ENC_HEADER_SIZE);

        if (!pt) {
            // Authentication tag failed — possible tampering
            closed_ = true;
            return std::nullopt;
        }

        last_recv_nonce_ = hdr.nonce_counter;
        bytes_recv_ += ENC_HEADER_SIZE + ct.size();
        msgs_recv_++;

        return ReceivedMessage{
            .type          = (proto::MsgType)hdr.msg_type,
            .flags         = hdr.flags,
            .payload       = std::move(*pt),
            .nonce_counter = hdr.nonce_counter
        };
    }

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------
    uint64_t bytes_sent() const { return bytes_sent_; }
    uint64_t bytes_recv() const { return bytes_recv_; }
    uint64_t msgs_sent()  const { return msgs_sent_; }
    uint64_t msgs_recv()  const { return msgs_recv_; }

    void close() {
        if (!closed_.exchange(true)) {
            send(proto::MsgType::GOODBYE);
        }
    }

private:
    TcpStream      stream_;
    NodeId         peer_node_id_;
    PublicKey      peer_public_key_;
    SessionKeys    keys_;
    uint64_t       established_at_ms_;

    std::mutex     send_mu_;
    std::atomic<bool> closed_{false};

    uint64_t       last_recv_nonce_ = 0;
    uint64_t       bytes_sent_      = 0;
    uint64_t       bytes_recv_      = 0;
    uint64_t       msgs_sent_       = 0;
    uint64_t       msgs_recv_       = 0;
};

} // namespace idn
