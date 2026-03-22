#pragma once
// ============================================================================
// identity.hpp — Core identity primitives for Identity Network
// "The network endpoint is a cryptographic identity. IP is only a carrier."
// ============================================================================

#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <optional>
#include <memory>
#include <span>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

namespace idn {

// ---------------------------------------------------------------------------
// NodeId: 32-byte SHA-256(public_key) — canonical address of a node
// ---------------------------------------------------------------------------
struct NodeId {
    std::array<uint8_t, 32> bytes{};

    bool operator==(const NodeId& o) const noexcept { return bytes == o.bytes; }
    bool operator!=(const NodeId& o) const noexcept { return bytes != o.bytes; }
    bool operator< (const NodeId& o) const noexcept { return bytes < o.bytes; }

    // Hex string, first 16 bytes for display (32 hex chars = "fingerprint")
    std::string to_hex() const {
        static constexpr char hex[] = "0123456789abcdef";
        std::string out(64, '\0');
        for (int i = 0; i < 32; ++i) {
            out[i*2]   = hex[(bytes[i] >> 4) & 0xF];
            out[i*2+1] = hex[ bytes[i]       & 0xF];
        }
        return out;
    }

    // Short fingerprint: "a1b2:c3d4:e5f6:7890"
    std::string fingerprint() const {
        auto h = to_hex();
        return h.substr(0,4)+":"+h.substr(4,4)+":"+h.substr(8,4)+":"+h.substr(12,4);
    }

    static NodeId from_hex(const std::string& s) {
        if (s.size() != 64) throw std::invalid_argument("NodeId hex must be 64 chars");
        NodeId id;
        for (int i = 0; i < 32; ++i) {
            auto nibble = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                throw std::invalid_argument("bad hex char");
            };
            id.bytes[i] = (nibble(s[i*2]) << 4) | nibble(s[i*2+1]);
        }
        return id;
    }

    static NodeId from_bytes(const uint8_t* data, size_t len) {
        NodeId id;
        SHA256(data, len, id.bytes.data());
        return id;
    }
};

// ---------------------------------------------------------------------------
// Base64 utility (no external deps)
// ---------------------------------------------------------------------------
namespace base64 {
    static constexpr char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    inline std::string encode(const uint8_t* data, size_t len) {
        std::string out;
        out.reserve(((len + 2) / 3) * 4);
        for (size_t i = 0; i < len; i += 3) {
            uint32_t v = ((uint32_t)data[i] << 16)
                       | (i+1 < len ? (uint32_t)data[i+1] << 8 : 0)
                       | (i+2 < len ? (uint32_t)data[i+2]      : 0);
            out += kTable[(v >> 18) & 0x3F];
            out += kTable[(v >> 12) & 0x3F];
            out += (i+1 < len) ? kTable[(v >> 6) & 0x3F] : '=';
            out += (i+2 < len) ? kTable[ v       & 0x3F] : '=';
        }
        return out;
    }

    inline std::vector<uint8_t> decode(const std::string& s) {
        auto val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        };
        std::vector<uint8_t> out;
        out.reserve(s.size() * 3 / 4);
        for (size_t i = 0; i + 3 < s.size(); i += 4) {
            int a = val(s[i]), b = val(s[i+1]), c = val(s[i+2]), d = val(s[i+3]);
            if (a < 0 || b < 0) break;
            out.push_back((a << 2) | (b >> 4));
            if (s[i+2] != '=' && c >= 0) out.push_back(((b & 0xF) << 4) | (c >> 2));
            if (s[i+3] != '=' && d >= 0) out.push_back(((c & 0x3) << 6) | d);
        }
        return out;
    }
}

// ---------------------------------------------------------------------------
// PublicKey: Ed25519 public key (32 bytes raw)
// ---------------------------------------------------------------------------
struct PublicKey {
    std::array<uint8_t, 32> bytes{};

    std::string to_base64() const {
        return base64::encode(bytes.data(), 32);
    }

    static PublicKey from_base64(const std::string& s) {
        auto v = base64::decode(s);
        if (v.size() != 32) throw std::invalid_argument("PublicKey must be 32 bytes");
        PublicKey pk;
        std::copy(v.begin(), v.end(), pk.bytes.begin());
        return pk;
    }

    NodeId to_node_id() const {
        return NodeId::from_bytes(bytes.data(), 32);
    }

    bool operator==(const PublicKey& o) const noexcept { return bytes == o.bytes; }
};

// ---------------------------------------------------------------------------
// NodeIdentity: Long-term identity keypair (Ed25519)
// ---------------------------------------------------------------------------
class NodeIdentity {
public:
    NodeIdentity() = default;

    // Generate a new identity keypair
    static NodeIdentity generate() {
        NodeIdentity id;
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("EVP_PKEY_keygen_init failed");
        }
        if (EVP_PKEY_keygen(ctx, &id.pkey_) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("EVP_PKEY_keygen failed");
        }
        EVP_PKEY_CTX_free(ctx);
        id.extract_keys();
        return id;
    }

    // Load from raw bytes (private key seed, 32 bytes)
    static NodeIdentity from_private_bytes(const std::vector<uint8_t>& priv_seed) {
        if (priv_seed.size() != 32)
            throw std::invalid_argument("Ed25519 private seed must be 32 bytes");
        NodeIdentity id;
        id.pkey_ = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr, priv_seed.data(), 32);
        if (!id.pkey_) throw std::runtime_error("Failed to load Ed25519 private key");
        id.extract_keys();
        return id;
    }

    ~NodeIdentity() {
        if (pkey_) EVP_PKEY_free(pkey_);
    }

    // Non-copyable, movable
    NodeIdentity(const NodeIdentity&) = delete;
    NodeIdentity& operator=(const NodeIdentity&) = delete;

    NodeIdentity(NodeIdentity&& o) noexcept
        : pkey_(o.pkey_), public_key_(o.public_key_),
          private_seed_(std::move(o.private_seed_)), node_id_(o.node_id_) {
        o.pkey_ = nullptr;
    }

    NodeIdentity& operator=(NodeIdentity&& o) noexcept {
        if (this != &o) {
            if (pkey_) EVP_PKEY_free(pkey_);
            pkey_ = o.pkey_; o.pkey_ = nullptr;
            public_key_ = o.public_key_;
            private_seed_ = std::move(o.private_seed_);
            node_id_ = o.node_id_;
        }
        return *this;
    }

    const PublicKey& public_key() const { return public_key_; }
    const NodeId& node_id() const { return node_id_; }
    const std::vector<uint8_t>& private_seed() const { return private_seed_; }

    // Sign arbitrary data — returns 64-byte Ed25519 signature
    std::array<uint8_t, 64> sign(const uint8_t* data, size_t len) const {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
        if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey_) <= 0) {
            EVP_MD_CTX_free(ctx); throw std::runtime_error("DigestSignInit failed");
        }
        size_t siglen = 64;
        std::array<uint8_t, 64> sig{};
        if (EVP_DigestSign(ctx, sig.data(), &siglen, data, len) <= 0) {
            EVP_MD_CTX_free(ctx); throw std::runtime_error("DigestSign failed");
        }
        EVP_MD_CTX_free(ctx);
        return sig;
    }

    std::array<uint8_t, 64> sign(std::span<const uint8_t> data) const {
        return sign(data.data(), data.size());
    }

    // Verify signature against this identity's public key
    bool verify(const uint8_t* data, size_t dlen,
                const uint8_t* sig,  size_t slen) const {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return false;
        if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey_) <= 0) {
            EVP_MD_CTX_free(ctx); return false;
        }
        int r = EVP_DigestVerify(ctx, sig, slen, data, dlen);
        EVP_MD_CTX_free(ctx);
        return r == 1;
    }

    std::string display() const {
        return "NodeId(" + node_id_.fingerprint() + ")  PubKey(" +
               public_key_.to_base64().substr(0, 16) + "...)";
    }

private:
    EVP_PKEY* pkey_ = nullptr;
    PublicKey public_key_;
    std::vector<uint8_t> private_seed_;
    NodeId node_id_;

    void extract_keys() {
        // Extract public key raw bytes
        size_t pub_len = 32;
        EVP_PKEY_get_raw_public_key(pkey_, public_key_.bytes.data(), &pub_len);

        // Extract private key seed raw bytes
        private_seed_.resize(32);
        size_t priv_len = 32;
        EVP_PKEY_get_raw_private_key(pkey_, private_seed_.data(), &priv_len);

        // Compute NodeId = SHA256(public_key)
        node_id_ = public_key_.to_node_id();
    }
};

// Verify a signature against any public key (not just our own)
inline bool verify_signature(const PublicKey& pk,
                              const uint8_t* data, size_t dlen,
                              const uint8_t* sig,  size_t slen) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, pk.bytes.data(), 32);
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey);
    int r = EVP_DigestVerify(ctx, sig, slen, data, dlen);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return r == 1;
}

} // namespace idn
