#pragma once
// ============================================================================
// crypto.hpp — Session key establishment and authenticated encryption
// X25519 ECDH for ephemeral key exchange, AES-256-GCM for AEAD encryption
// ============================================================================

#include "identity.hpp"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <span>

namespace idn {

// ---------------------------------------------------------------------------
// EphemeralKeyPair: X25519 key for one-time use in a single handshake
// ---------------------------------------------------------------------------
class EphemeralKeyPair {
public:
    EphemeralKeyPair() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!ctx) throw std::runtime_error("X25519 ctx failed");
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_keygen(ctx, &pkey_);
        EVP_PKEY_CTX_free(ctx);
        if (!pkey_) throw std::runtime_error("X25519 keygen failed");

        size_t len = 32;
        EVP_PKEY_get_raw_public_key(pkey_, pub_.data(), &len);
    }

    ~EphemeralKeyPair() { if (pkey_) EVP_PKEY_free(pkey_); }
    EphemeralKeyPair(const EphemeralKeyPair&) = delete;
    EphemeralKeyPair(EphemeralKeyPair&& o) noexcept : pkey_(o.pkey_), pub_(o.pub_) {
        o.pkey_ = nullptr;
    }

    const std::array<uint8_t, 32>& public_key_bytes() const { return pub_; }

    // Perform DH with peer's public X25519 key → 32-byte shared secret
    std::array<uint8_t, 32> dh(const std::array<uint8_t, 32>& peer_pub) const {
        EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519, nullptr, peer_pub.data(), 32);
        if (!peer) throw std::runtime_error("peer X25519 key failed");

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, peer);

        size_t secret_len = 32;
        std::array<uint8_t, 32> secret{};
        EVP_PKEY_derive(ctx, secret.data(), &secret_len);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer);
        return secret;
    }

private:
    EVP_PKEY* pkey_ = nullptr;
    std::array<uint8_t, 32> pub_{};
};

// ---------------------------------------------------------------------------
// HKDF-SHA256: derive keying material from shared secret + context
// ---------------------------------------------------------------------------
inline std::vector<uint8_t> hkdf_sha256(
    const uint8_t* ikm,   size_t ikm_len,
    const uint8_t* salt,  size_t salt_len,
    const uint8_t* info,  size_t info_len,
    size_t out_len)
{
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    uint8_t prk[32];
    unsigned int prk_len = 32;
    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk, &prk_len))
        throw std::runtime_error("HKDF extract failed");

    // Expand
    std::vector<uint8_t> okm;
    okm.reserve(out_len);
    uint8_t T[32]{};
    uint8_t counter = 1;
    size_t t_len = 0;

    while (okm.size() < out_len) {
        std::vector<uint8_t> input(t_len + info_len + 1);
        if (t_len) memcpy(input.data(), T, t_len);
        memcpy(input.data() + t_len, info, info_len);
        input[t_len + info_len] = counter++;

        unsigned int out32 = 32;
        HMAC(EVP_sha256(), prk, 32, input.data(), input.size(), T, &out32);
        t_len = 32;

        size_t take = std::min((size_t)32, out_len - okm.size());
        okm.insert(okm.end(), T, T + take);
    }
    return okm;
}

// ---------------------------------------------------------------------------
// SessionKeys: derived from ECDH shared secret
// Each direction has its own key + nonce counter for AES-256-GCM
// ---------------------------------------------------------------------------
struct SessionKeys {
    std::array<uint8_t, 32> send_key{};   // AES-256-GCM key for outbound
    std::array<uint8_t, 32> recv_key{};   // AES-256-GCM key for inbound
    std::array<uint8_t, 12> send_iv{};    // Base IV for outbound (first 12 bytes)
    std::array<uint8_t, 12> recv_iv{};    // Base IV for inbound
    uint64_t send_nonce = 0;              // Counter for outbound nonces
    uint64_t recv_nonce = 0;              // Counter for inbound nonces

    // Derive from raw DH output, initiator/responder flag, and both ephemeral pubkeys
    static SessionKeys derive(
        const std::array<uint8_t, 32>& dh_secret,
        const std::array<uint8_t, 32>& eph_init_pub,
        const std::array<uint8_t, 32>& eph_resp_pub,
        bool we_are_initiator)
    {
        // Salt = eph_init_pub || eph_resp_pub
        uint8_t salt[64];
        memcpy(salt,    eph_init_pub.data(), 32);
        memcpy(salt+32, eph_resp_pub.data(), 32);

        static const uint8_t info_send_i[] = "idn-v1-init-to-resp-key";
        static const uint8_t info_send_r[] = "idn-v1-resp-to-init-key";
        static const uint8_t info_iv_i[]   = "idn-v1-init-to-resp-iv";
        static const uint8_t info_iv_r[]   = "idn-v1-resp-to-init-iv";

        auto k_i2r = hkdf_sha256(dh_secret.data(), 32, salt, 64,
                                  info_send_i, sizeof(info_send_i)-1, 32);
        auto k_r2i = hkdf_sha256(dh_secret.data(), 32, salt, 64,
                                  info_send_r, sizeof(info_send_r)-1, 32);
        auto iv_i  = hkdf_sha256(dh_secret.data(), 32, salt, 64,
                                  info_iv_i, sizeof(info_iv_i)-1, 12);
        auto iv_r  = hkdf_sha256(dh_secret.data(), 32, salt, 64,
                                  info_iv_r, sizeof(info_iv_r)-1, 12);

        SessionKeys sk;
        if (we_are_initiator) {
            std::copy(k_i2r.begin(), k_i2r.end(), sk.send_key.begin());
            std::copy(k_r2i.begin(), k_r2i.end(), sk.recv_key.begin());
            std::copy(iv_i.begin(),  iv_i.end(),  sk.send_iv.begin());
            std::copy(iv_r.begin(),  iv_r.end(),  sk.recv_iv.begin());
        } else {
            std::copy(k_r2i.begin(), k_r2i.end(), sk.send_key.begin());
            std::copy(k_i2r.begin(), k_i2r.end(), sk.recv_key.begin());
            std::copy(iv_r.begin(),  iv_r.end(),  sk.send_iv.begin());
            std::copy(iv_i.begin(),  iv_i.end(),  sk.recv_iv.begin());
        }
        return sk;
    }

    // Build nonce: base_iv XOR big-endian counter
    static std::array<uint8_t, 12> make_nonce(
        const std::array<uint8_t, 12>& base_iv, uint64_t counter)
    {
        auto nonce = base_iv;
        // XOR last 8 bytes with counter (big-endian)
        for (int i = 0; i < 8; ++i) {
            nonce[4 + i] ^= (uint8_t)((counter >> (56 - i * 8)) & 0xFF);
        }
        return nonce;
    }
};

// ---------------------------------------------------------------------------
// AES-256-GCM AEAD
// ---------------------------------------------------------------------------
class AESGCM {
public:
    // Encrypt plaintext → ciphertext || tag (16 bytes)
    // aad = additional authenticated data (e.g., message header)
    static std::vector<uint8_t> encrypt(
        const uint8_t* key,        // 32 bytes
        const uint8_t* nonce,      // 12 bytes
        const uint8_t* plaintext,  size_t pt_len,
        const uint8_t* aad,        size_t aad_len)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce);

        if (aad_len > 0) {
            int outl = 0;
            EVP_EncryptUpdate(ctx, nullptr, &outl, aad, (int)aad_len);
        }

        std::vector<uint8_t> ct(pt_len + 16);
        int outl = 0;
        EVP_EncryptUpdate(ctx, ct.data(), &outl, plaintext, (int)pt_len);
        int final_outl = 0;
        EVP_EncryptFinal_ex(ctx, ct.data() + outl, &final_outl);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ct.data() + pt_len);
        EVP_CIPHER_CTX_free(ctx);
        return ct;
    }

    // Decrypt ciphertext+tag → plaintext; returns empty on auth failure
    static std::optional<std::vector<uint8_t>> decrypt(
        const uint8_t* key,
        const uint8_t* nonce,
        const uint8_t* ciphertext, size_t ct_len,  // includes 16-byte tag
        const uint8_t* aad,        size_t aad_len)
    {
        if (ct_len < 16) return std::nullopt;
        size_t data_len = ct_len - 16;
        const uint8_t* tag = ciphertext + data_len;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce);

        if (aad_len > 0) {
            int outl = 0;
            EVP_DecryptUpdate(ctx, nullptr, &outl, aad, (int)aad_len);
        }

        std::vector<uint8_t> pt(data_len);
        int outl = 0;
        EVP_DecryptUpdate(ctx, pt.data(), &outl, ciphertext, (int)data_len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<uint8_t*>(tag));
        int ok = EVP_DecryptFinal_ex(ctx, pt.data() + outl, &outl);
        EVP_CIPHER_CTX_free(ctx);

        if (ok != 1) return std::nullopt;
        return pt;
    }
};

} // namespace idn
