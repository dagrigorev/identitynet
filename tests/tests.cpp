// ============================================================================
// tests.cpp — Identity Network test suite
// Run: ./identitynet-tests
// ============================================================================

#include "identity.hpp"
#include "crypto.hpp"
#include "protocol.hpp"
#include "transport.hpp"
#include "handshake.hpp"
#include "session.hpp"
#include "discovery.hpp"
#include "authz.hpp"
#include "keystore.hpp"
#include "server.hpp"
#include "client.hpp"

#include <cassert>
#include <cstdio>
#include <vector>
#include <thread>
#include <filesystem>
#include <stdexcept>
#include <chrono>

// ---------------------------------------------------------------------------
// Test framework
// ---------------------------------------------------------------------------
static int g_passed = 0, g_failed = 0;

#define TEST(name) \
    static void test_##name(); \
    static struct _reg_##name { _reg_##name() { \
        printf("  %-55s", #name "..."); fflush(stdout); \
        try { test_##name(); printf("PASS\n"); g_passed++; } \
        catch(const std::exception& e) { printf("FAIL: %s\n", e.what()); g_failed++; } \
        catch(...) { printf("FAIL: unknown exception\n"); g_failed++; } \
    }} _r_##name; \
    static void test_##name()

#define ASSERT(expr) \
    if (!(expr)) throw std::runtime_error(std::string("Assertion failed: ") + #expr)

#define ASSERT_EQ(a, b) \
    { auto _a = (a); auto _b = (b); \
      if (_a != _b) throw std::runtime_error(std::string("Expected equal: ") + #a + " == " + #b); }

#define ASSERT_THROWS(expr) \
    do { bool _threw = false; \
         try { expr; } catch(...) { _threw = true; } \
         if (!_threw) throw std::runtime_error("Expected exception: " #expr); \
    } while(0)

// ===========================================================================
// LAYER 1: Identity
// ===========================================================================
TEST(identity_generate) {
    auto id = idn::NodeIdentity::generate();
    auto zero32 = std::array<uint8_t,32>{};
    ASSERT(id.public_key().bytes != zero32);
    ASSERT(id.node_id().bytes    != zero32);
    ASSERT(id.private_seed().size() == 32);
}

TEST(identity_node_id_is_sha256_of_pubkey) {
    auto id = idn::NodeIdentity::generate();
    idn::NodeId computed = idn::NodeId::from_bytes(
        id.public_key().bytes.data(), 32);
    ASSERT_EQ(computed, id.node_id());
}

TEST(identity_sign_verify) {
    auto id = idn::NodeIdentity::generate();
    const uint8_t msg[] = "identity network test message";
    auto sig = id.sign(msg, sizeof(msg));
    ASSERT(sig.size() == 64);
    ASSERT(id.verify(msg, sizeof(msg), sig.data(), 64));
}

TEST(identity_sign_tampered_fails) {
    auto id = idn::NodeIdentity::generate();
    const uint8_t msg[] = "original message";
    auto sig = id.sign(msg, sizeof(msg));
    const uint8_t tampered[] = "tampered message";
    ASSERT(!id.verify(tampered, sizeof(tampered), sig.data(), 64));
}

TEST(identity_cross_verify) {
    auto id1 = idn::NodeIdentity::generate();
    auto id2 = idn::NodeIdentity::generate();
    const uint8_t msg[] = "test";
    auto sig = id1.sign(msg, sizeof(msg));
    // id2's key should NOT verify id1's signature
    ASSERT(!idn::verify_signature(id2.public_key(), msg, sizeof(msg),
                                   sig.data(), 64));
    // id1's key SHOULD verify id1's signature
    ASSERT(idn::verify_signature(id1.public_key(), msg, sizeof(msg),
                                  sig.data(), 64));
}

TEST(identity_serialize_round_trip) {
    auto id = idn::NodeIdentity::generate();
    auto b64 = id.public_key().to_base64();
    ASSERT(!b64.empty());
    auto pk2 = idn::PublicKey::from_base64(b64);
    ASSERT_EQ(pk2, id.public_key());
}

TEST(identity_node_id_hex_round_trip) {
    auto id = idn::NodeIdentity::generate();
    auto hex = id.node_id().to_hex();
    ASSERT(hex.size() == 64);
    auto id2 = idn::NodeId::from_hex(hex);
    ASSERT_EQ(id2, id.node_id());
}

TEST(identity_load_from_seed) {
    auto id1 = idn::NodeIdentity::generate();
    auto seed = id1.private_seed();
    auto id2 = idn::NodeIdentity::from_private_bytes(seed);
    ASSERT_EQ(id1.public_key(), id2.public_key());
    ASSERT_EQ(id1.node_id(),    id2.node_id());
}

TEST(identity_two_different_nodes_have_different_ids) {
    auto id1 = idn::NodeIdentity::generate();
    auto id2 = idn::NodeIdentity::generate();
    ASSERT(id1.node_id() != id2.node_id());
    ASSERT(id1.public_key() != id2.public_key());
}

// ===========================================================================
// LAYER 2: Crypto
// ===========================================================================
TEST(crypto_x25519_dh_commutative) {
    idn::EphemeralKeyPair a, b;
    auto sa = a.dh(b.public_key_bytes());
    auto sb = b.dh(a.public_key_bytes());
    ASSERT_EQ(sa, sb);
}

TEST(crypto_hkdf_deterministic) {
    uint8_t ikm[] = "test-key-material";
    uint8_t salt[] = "salt";
    uint8_t info[] = "context";
    auto k1 = idn::hkdf_sha256(ikm, 17, salt, 4, info, 7, 32);
    auto k2 = idn::hkdf_sha256(ikm, 17, salt, 4, info, 7, 32);
    ASSERT_EQ(k1, k2);
}

TEST(crypto_hkdf_different_info_different_keys) {
    uint8_t ikm[] = "shared-secret";
    uint8_t salt[] = "test";
    uint8_t info1[] = "send-key";
    uint8_t info2[] = "recv-key";
    auto k1 = idn::hkdf_sha256(ikm, 13, salt, 4, info1, 8, 32);
    auto k2 = idn::hkdf_sha256(ikm, 13, salt, 4, info2, 8, 32);
    ASSERT(k1 != k2);
}

TEST(crypto_aes_gcm_encrypt_decrypt) {
    uint8_t key[32], nonce[12];
    RAND_bytes(key, 32);
    RAND_bytes(nonce, 12);

    std::vector<uint8_t> pt = {1,2,3,4,5,6,7,8,9,10};
    uint8_t aad[] = "authenticated header";

    auto ct = idn::AESGCM::encrypt(key, nonce, pt.data(), pt.size(),
                                    aad, sizeof(aad));
    ASSERT(ct.size() == pt.size() + 16); // +tag

    auto recovered = idn::AESGCM::decrypt(key, nonce, ct.data(), ct.size(),
                                           aad, sizeof(aad));
    ASSERT(recovered.has_value());
    ASSERT_EQ(*recovered, pt);
}

TEST(crypto_aes_gcm_tampered_ciphertext_fails) {
    uint8_t key[32], nonce[12];
    RAND_bytes(key, 32); RAND_bytes(nonce, 12);
    std::vector<uint8_t> pt = {1,2,3,4,5};
    uint8_t aad[] = "hdr";
    auto ct = idn::AESGCM::encrypt(key, nonce, pt.data(), pt.size(), aad, 3);
    ct[0] ^= 0xFF; // tamper
    auto result = idn::AESGCM::decrypt(key, nonce, ct.data(), ct.size(), aad, 3);
    ASSERT(!result.has_value());
}

TEST(crypto_aes_gcm_wrong_key_fails) {
    uint8_t key1[32], key2[32], nonce[12];
    RAND_bytes(key1, 32); RAND_bytes(key2, 32); RAND_bytes(nonce, 12);
    std::vector<uint8_t> pt = {0xAB, 0xCD};
    auto ct = idn::AESGCM::encrypt(key1, nonce, pt.data(), 2, nullptr, 0);
    auto result = idn::AESGCM::decrypt(key2, nonce, ct.data(), ct.size(), nullptr, 0);
    ASSERT(!result.has_value());
}

TEST(crypto_session_keys_initiator_responder_match) {
    idn::EphemeralKeyPair init_eph, resp_eph;
    auto dh_i = init_eph.dh(resp_eph.public_key_bytes());
    auto dh_r = resp_eph.dh(init_eph.public_key_bytes());
    ASSERT_EQ(dh_i, dh_r);

    auto sk_i = idn::SessionKeys::derive(dh_i,
                    init_eph.public_key_bytes(), resp_eph.public_key_bytes(), true);
    auto sk_r = idn::SessionKeys::derive(dh_r,
                    init_eph.public_key_bytes(), resp_eph.public_key_bytes(), false);

    // Initiator's send key == Responder's recv key
    ASSERT_EQ(sk_i.send_key, sk_r.recv_key);
    ASSERT_EQ(sk_r.send_key, sk_i.recv_key);
    ASSERT_EQ(sk_i.send_iv,  sk_r.recv_iv);
    ASSERT_EQ(sk_r.send_iv,  sk_i.recv_iv);
}

// ===========================================================================
// LAYER 3: Protocol framing
// ===========================================================================
TEST(protocol_frame_round_trip) {
    std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    auto msg = idn::proto::frame(idn::proto::MsgType::ECHO_REQ, payload);
    ASSERT(msg.size() == 12 + 4);

    auto* hdr = reinterpret_cast<idn::proto::WireHeader*>(msg.data());
    ASSERT(idn::proto::read_u32_be(reinterpret_cast<uint8_t*>(&hdr->magic))
           == idn::proto::MAGIC);
    ASSERT(hdr->msg_type == (uint8_t)idn::proto::MsgType::ECHO_REQ);
    ASSERT(idn::proto::read_u32_be(reinterpret_cast<uint8_t*>(&hdr->payload_len)) == 4);
}

TEST(protocol_ping_payload_round_trip) {
    idn::proto::PingPayload p;
    p.request_id   = 0xDEADBEEFCAFEBABEULL;
    p.timestamp_ms = 1234567890123ULL;
    auto s = p.serialize();
    ASSERT(s.size() == 16);
    auto p2 = idn::proto::PingPayload::deserialize(s.data(), s.size());
    ASSERT_EQ(p.request_id,   p2.request_id);
    ASSERT_EQ(p.timestamp_ms, p2.timestamp_ms);
}

TEST(protocol_echo_payload_round_trip) {
    idn::proto::EchoPayload e;
    e.request_id = 42;
    e.message    = "Hello, Identity Network!";
    auto s = e.serialize();
    auto e2 = idn::proto::EchoPayload::deserialize(s.data(), s.size());
    ASSERT_EQ(e.request_id, e2.request_id);
    ASSERT_EQ(e.message,    e2.message);
}

// ===========================================================================
// LAYER 4: Authorization
// ===========================================================================
TEST(authz_allow_all) {
    auto policy = idn::AuthorizationPolicy::allow_all();
    auto id = idn::NodeIdentity::generate();
    ASSERT(policy.is_allowed(id.node_id()));
}

TEST(authz_allowlist_permit) {
    auto id1 = idn::NodeIdentity::generate();
    auto id2 = idn::NodeIdentity::generate();
    auto policy = idn::AuthorizationPolicy::allowlist({id1.node_id()});
    ASSERT( policy.is_allowed(id1.node_id()));
    ASSERT(!policy.is_allowed(id2.node_id()));
}

TEST(authz_deny_overrides_allowlist) {
    auto id = idn::NodeIdentity::generate();
    auto policy = idn::AuthorizationPolicy::allow_all();
    policy.deny(id.node_id());
    ASSERT(!policy.is_allowed(id.node_id()));
}

TEST(authz_acl_file_save_load) {
    auto id1 = idn::NodeIdentity::generate();
    auto id2 = idn::NodeIdentity::generate();
    auto id3 = idn::NodeIdentity::generate();

    auto policy = idn::AuthorizationPolicy::allowlist({id1.node_id(), id2.node_id()});
    policy.save_to_file("/tmp/test_acl.txt");

    auto loaded = idn::AuthorizationPolicy::load_from_file("/tmp/test_acl.txt");
    ASSERT( loaded.is_allowed(id1.node_id()));
    ASSERT( loaded.is_allowed(id2.node_id()));
    ASSERT(!loaded.is_allowed(id3.node_id()));

    std::filesystem::remove("/tmp/test_acl.txt");
}

// ===========================================================================
// LAYER 5: KeyStore
// ===========================================================================
TEST(keystore_save_load_round_trip) {
    auto id1 = idn::NodeIdentity::generate();
    idn::KeyStore::save(id1, "/tmp/test_identity.key");
    auto id2 = idn::KeyStore::load("/tmp/test_identity.key");
    ASSERT_EQ(id1.public_key(), id2.public_key());
    ASSERT_EQ(id1.node_id(),    id2.node_id());
    std::filesystem::remove("/tmp/test_identity.key");
}

TEST(keystore_load_or_generate_creates_file) {
    std::filesystem::remove("/tmp/test_new.key");
    ASSERT(!std::filesystem::exists("/tmp/test_new.key"));
    auto id = idn::KeyStore::load_or_generate("/tmp/test_new.key");
    ASSERT(std::filesystem::exists("/tmp/test_new.key"));
    auto id2 = idn::KeyStore::load_or_generate("/tmp/test_new.key");
    ASSERT_EQ(id.node_id(), id2.node_id());
    std::filesystem::remove("/tmp/test_new.key");
}

// ===========================================================================
// INTEGRATION: Full handshake over localhost
// ===========================================================================
TEST(integration_handshake_mutual_auth) {
    auto server_id = idn::NodeIdentity::generate();
    auto client_id = idn::NodeIdentity::generate();

    // Find a free port
    uint16_t port = 19001;

    std::exception_ptr server_exc;
    idn::HandshakeResult server_result;
    bool server_done = false;

    // Server thread
    std::thread server_thread([&]() {
        try {
            idn::TcpListener listener = idn::TcpListener::bind({"0.0.0.0", port});
            auto [stream, _] = listener.accept();
            idn::IdentityHandshake hs(server_id, idn::HandshakeRole::RESPONDER);
            server_result = hs.run(stream);
            stream.send_frame(idn::proto::MsgType::SESSION_ACK);
            server_done = true;
        } catch (...) {
            server_exc = std::current_exception();
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Client
    idn::HandshakeResult client_result;
    try {
        auto stream = idn::TcpStream::connect({"127.0.0.1", port});
        idn::IdentityHandshake hs(client_id, idn::HandshakeRole::INITIATOR,
                                   server_id.public_key());
        client_result = hs.run(stream);
    } catch (...) {
        server_thread.join();
        throw;
    }

    server_thread.join();
    if (server_exc) std::rethrow_exception(server_exc);

    // Verify both sides see correct peer identity
    ASSERT_EQ(client_result.peer_node_id, server_id.node_id());
    ASSERT_EQ(server_result.peer_node_id, client_id.node_id());

    // Verify session keys match
    ASSERT_EQ(client_result.session_keys.send_key, server_result.session_keys.recv_key);
    ASSERT_EQ(server_result.session_keys.send_key, client_result.session_keys.recv_key);
}

TEST(integration_handshake_wrong_pubkey_rejected) {
    auto server_id  = idn::NodeIdentity::generate();
    auto client_id  = idn::NodeIdentity::generate();
    auto impostor   = idn::NodeIdentity::generate();

    uint16_t port = 19002;
    std::thread server_thread([&]() {
        try {
            idn::TcpListener listener = idn::TcpListener::bind({"0.0.0.0", port});
            auto [stream, _] = listener.accept();
            idn::IdentityHandshake hs(server_id, idn::HandshakeRole::RESPONDER);
            hs.run(stream);
            stream.send_frame(idn::proto::MsgType::SESSION_ACK);
        } catch (...) {}
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    bool threw = false;
    try {
        auto stream = idn::TcpStream::connect({"127.0.0.1", port});
        // Client expects impostor's key, but server has server_id's key
        idn::IdentityHandshake hs(client_id, idn::HandshakeRole::INITIATOR,
                                   impostor.public_key()); // wrong key!
        hs.run(stream);
    } catch (...) {
        threw = true;
    }

    server_thread.join();
    ASSERT(threw); // Must throw — MITM / wrong identity
}

// ===========================================================================
// INTEGRATION: Full encrypted session
// ===========================================================================
TEST(integration_secure_session_echo) {
    auto server_id = idn::NodeIdentity::generate();
    auto client_id = idn::NodeIdentity::generate();
    uint16_t port  = 19003;

    std::string received_echo;
    std::thread server_thread([&]() {
        try {
            idn::TcpListener listener = idn::TcpListener::bind({"0.0.0.0", port});
            auto [stream, _] = listener.accept();
            idn::IdentityHandshake hs(server_id, idn::HandshakeRole::RESPONDER);
            auto result = hs.run(stream);
            stream.send_frame(idn::proto::MsgType::SESSION_ACK);

            idn::SecureSession sess(std::move(stream), result);
            auto msg = sess.recv(5000);
            if (msg && msg->type == idn::proto::MsgType::ECHO_REQ) {
                auto req = idn::proto::EchoPayload::deserialize(
                    msg->payload.data(), msg->payload.size());
                received_echo = req.message;

                idn::proto::EchoPayload resp;
                resp.request_id = req.request_id;
                resp.message    = "ECHO:" + req.message;
                sess.send(idn::proto::MsgType::ECHO_RESP, resp.serialize());
            }
        } catch (...) {}
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::string echo_resp;
    {
        auto stream = idn::TcpStream::connect({"127.0.0.1", port});
        idn::IdentityHandshake hs(client_id, idn::HandshakeRole::INITIATOR,
                                   server_id.public_key());
        auto result = hs.run(stream);

        // Read SESSION_ACK
        stream.read_frame(3000);

        idn::SecureSession sess(std::move(stream), result);

        idn::proto::EchoPayload req;
        req.request_id = 1;
        req.message    = "hello_secure";
        sess.send(idn::proto::MsgType::ECHO_REQ, req.serialize());

        auto msg = sess.recv(5000);
        ASSERT(msg.has_value());
        ASSERT(msg->type == idn::proto::MsgType::ECHO_RESP);
        auto resp = idn::proto::EchoPayload::deserialize(
            msg->payload.data(), msg->payload.size());
        echo_resp = resp.message;
    }

    server_thread.join();
    ASSERT_EQ(received_echo, "hello_secure");
    ASSERT_EQ(echo_resp,     "ECHO:hello_secure");
}

// ===========================================================================
// INTEGRATION: Discovery server
// ===========================================================================
TEST(integration_discovery_register_lookup) {
    idn::DiscoveryServer disc_server(17750);
    disc_server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto id = idn::NodeIdentity::generate();
    idn::DiscoveryClient client({"127.0.0.1", 17750});

    bool ok = client.register_node(id, {"127.0.0.1", 19100});
    ASSERT(ok);

    auto rec = client.lookup_by_node_id(id.node_id());
    ASSERT(rec.has_value());
    ASSERT_EQ(rec->node_id,    id.node_id());
    ASSERT_EQ(rec->public_key, id.public_key());

    // Lookup by pubkey
    auto rec2 = client.lookup_by_pubkey(id.public_key());
    ASSERT(rec2.has_value());
    ASSERT_EQ(rec2->node_id, id.node_id());

    disc_server.stop();
}

TEST(integration_discovery_fake_registration_rejected) {
    idn::DiscoveryServer disc_server(17751);
    disc_server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto id = idn::NodeIdentity::generate();
    auto fake_id = idn::NodeIdentity::generate();

    // Try to register id but sign with fake_id — should fail
    uint64_t ts = idn::now_ms();
    std::string endpoint = "127.0.0.1:19200";
    std::string transcript = id.node_id().to_hex() + "|" + endpoint
                           + "|" + std::to_string(ts);
    // Sign with WRONG key
    auto sig = fake_id.sign((const uint8_t*)transcript.data(), transcript.size());
    std::string sig_b64 = idn::base64::encode(sig.data(), 64);

    // Build request manually
    std::ostringstream req;
    req << "{\"action\":\"register\""
        << ",\"public_key\":\"" << id.public_key().to_base64() << "\""
        << ",\"endpoint\":\"" << endpoint << "\""
        << ",\"timestamp\":" << ts
        << ",\"signature\":\"" << sig_b64 << "\"}";

    auto stream = idn::TcpStream::connect({"127.0.0.1", 17751});
    std::string r = req.str() + "\n";
    stream.send_all((const uint8_t*)r.data(), r.size());

    char buf[1024]; int pos = 0;
    while (pos < 1023) {
        uint8_t c;
        if (!stream.recv_exact(&c, 1, 2000)) break;
        if (c == '\n') break;
        buf[pos++] = (char)c;
    }
    buf[pos] = '\0';
    std::string resp(buf, pos);

    // Should be rejected
    ASSERT(resp.find("\"ok\":false") != std::string::npos ||
           resp.find("\"ok\": false") != std::string::npos);

    disc_server.stop();
}

// ===========================================================================
// INTEGRATION: Full end-to-end server+client
// ===========================================================================
TEST(integration_full_server_client_ping_echo) {
    auto server_key_path = "/tmp/test_srv.key";
    auto client_key_path = "/tmp/test_cli.key";
    std::filesystem::remove(server_key_path);
    std::filesystem::remove(client_key_path);

    // Start discovery
    idn::DiscoveryServer disc(17760);
    disc.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Start server
    idn::ServerConfig srv_cfg;
    srv_cfg.listen_port        = 19050;
    srv_cfg.identity_key_path  = server_key_path;
    srv_cfg.discovery_endpoint = "127.0.0.1:17760";
    srv_cfg.register_on_start  = true;
    srv_cfg.verbose            = false;

    idn::IdentityServer server(srv_cfg);
    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Client connects by node_id via discovery
    idn::ClientConfig cli_cfg;
    cli_cfg.identity_key_path  = client_key_path;
    cli_cfg.discovery_endpoint = "127.0.0.1:17760";
    cli_cfg.verbose            = false;

    idn::IdentityClient client(cli_cfg);

    auto sess = client.connect_by_node_id(server.identity().node_id());
    ASSERT(sess != nullptr);
    ASSERT(sess->peer_node_id() == server.identity().node_id());

    // Ping
    double rtt = idn::IdentityClient::ping(*sess);
    ASSERT(rtt >= 0 && rtt < 1000);

    // Echo
    std::string resp = idn::IdentityClient::echo(*sess, "integration test");
    ASSERT(resp.find("integration test") != std::string::npos);
    ASSERT(resp.find("echo") != std::string::npos);

    sess->close();
    server.stop();
    disc.stop();

    std::filesystem::remove(server_key_path);
    std::filesystem::remove(client_key_path);
}

TEST(integration_acl_deny) {
    auto server_key_path = "/tmp/test_acl_srv.key";
    auto client_key_path = "/tmp/test_acl_cli.key";
    std::filesystem::remove(server_key_path);
    std::filesystem::remove(client_key_path);

    idn::DiscoveryServer disc(17761);
    disc.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Create server with empty allowlist (deny all)
    auto acl_file = "/tmp/test_empty.acl";
    { std::ofstream f(acl_file); f << "# empty\n"; }

    idn::ServerConfig srv_cfg;
    srv_cfg.listen_port        = 19051;
    srv_cfg.identity_key_path  = server_key_path;
    srv_cfg.discovery_endpoint = "127.0.0.1:17761";
    srv_cfg.acl_path           = acl_file;
    srv_cfg.register_on_start  = true;
    srv_cfg.verbose            = false;

    idn::IdentityServer server(srv_cfg);
    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    idn::ClientConfig cli_cfg;
    cli_cfg.identity_key_path  = client_key_path;
    cli_cfg.discovery_endpoint = "127.0.0.1:17761";
    cli_cfg.verbose            = false;

    idn::IdentityClient client(cli_cfg);

    // Connection should fail (ACL deny)
    bool threw = false;
    try {
        auto sess = client.connect_by_node_id(server.identity().node_id());
        // If we get here, try to use the session — it should be broken
        idn::IdentityClient::ping(*sess);
    } catch (...) {
        threw = true;
    }
    ASSERT(threw);

    server.stop();
    disc.stop();

    std::filesystem::remove(server_key_path);
    std::filesystem::remove(client_key_path);
    std::filesystem::remove(acl_file);
}

// ===========================================================================
// Main
// ===========================================================================
int main(int argc, char* argv[]) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║     Identity Network — Test Suite                        ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("Layer 1: Identity primitives\n");
    printf("Layer 2: Cryptographic primitives\n");
    printf("Layer 3: Protocol framing\n");
    printf("Layer 4: Authorization policy\n");
    printf("Layer 5: Key store\n");
    printf("Integration: Handshake, Session, Discovery, Server+Client\n\n");

    // All tests registered via static initializers — already ran

    printf("\n══════════════════════════════════════════════════════════\n");
    printf("Results: %d passed, %d failed\n", g_passed, g_failed);

    if (g_failed > 0) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }
    printf("ALL TESTS PASSED ✓\n");
    return 0;
}
