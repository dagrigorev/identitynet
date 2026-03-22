#pragma once
// ============================================================================
// client.hpp — Identity Network client
//
// The ONLY way to connect is by identity:
//   connect_by_node_id(node_id)   — resolves via discovery → verifies identity
//   connect_by_pubkey(pubkey)     — resolves via discovery → pins to pubkey
//   connect_direct(pubkey, ep)    — bypasses discovery (known endpoint)
//
// IP:port is NEVER exposed in the public API.
// Identity is the only address that matters.
// ============================================================================

#include "handshake.hpp"
#include "session.hpp"
#include "discovery.hpp"
#include "keystore.hpp"
#include <optional>
#include <atomic>

namespace idn {

// ---------------------------------------------------------------------------
// ClientConfig
// ---------------------------------------------------------------------------
struct ClientConfig {
    std::string identity_key_path  = "client.key";
    std::string discovery_endpoint = "127.0.0.1:7700";
    int         connect_timeout_ms = 5000;
    bool        verbose            = true;
};

// ---------------------------------------------------------------------------
// IdentityClient
// ---------------------------------------------------------------------------
class IdentityClient {
public:
    explicit IdentityClient(ClientConfig cfg)
        : cfg_(std::move(cfg)),
          identity_(KeyStore::load_or_generate(cfg_.identity_key_path)) {

        if (cfg_.verbose) {
            printf("[client] Identity: %s\n", identity_.display().c_str());
        }
    }

    const NodeIdentity& identity() const { return identity_; }

    // -----------------------------------------------------------------------
    // CONNECT BY NODE_ID
    // Resolve node_id → (pubkey, transport_endpoint) via discovery,
    // then establish identity-authenticated session.
    // -----------------------------------------------------------------------
    std::unique_ptr<SecureSession> connect_by_node_id(const NodeId& target_id) {
        if (cfg_.verbose)
            printf("[client] Connecting to node_id: %s\n",
                   target_id.fingerprint().c_str());

        auto disc_ep = TransportEndpoint::from_string(cfg_.discovery_endpoint);
        DiscoveryClient disc(disc_ep);

        auto rec = disc.lookup_by_node_id(target_id);
        if (!rec) {
            throw std::runtime_error("Node not found in discovery: "
                                     + target_id.to_hex());
        }

        if (cfg_.verbose)
            printf("[client] Discovery: found %s @ %s\n",
                   rec->node_id.fingerprint().c_str(),
                   rec->transport_endpoint.c_str());

        // Connect with known pubkey — enables MITM protection
        return connect_direct(rec->public_key,
                               TransportEndpoint::from_string(rec->transport_endpoint));
    }

    // -----------------------------------------------------------------------
    // CONNECT BY PUBLIC KEY
    // Resolve pubkey → transport_endpoint via discovery,
    // pin the expected public key (MITM-resistant).
    // -----------------------------------------------------------------------
    std::unique_ptr<SecureSession> connect_by_pubkey(const PublicKey& target_pubkey) {
        if (cfg_.verbose)
            printf("[client] Connecting to pubkey: %s...\n",
                   target_pubkey.to_base64().substr(0,16).c_str());

        auto disc_ep = TransportEndpoint::from_string(cfg_.discovery_endpoint);
        DiscoveryClient disc(disc_ep);

        auto rec = disc.lookup_by_pubkey(target_pubkey);
        if (!rec) {
            throw std::runtime_error("Public key not found in discovery: "
                                     + target_pubkey.to_base64());
        }

        return connect_direct(target_pubkey,
                               TransportEndpoint::from_string(rec->transport_endpoint));
    }

    // -----------------------------------------------------------------------
    // CONNECT DIRECT (known endpoint + pubkey)
    // Bypasses discovery — useful when endpoint is already known.
    // Still performs full identity handshake and pins the expected pubkey.
    // -----------------------------------------------------------------------
    std::unique_ptr<SecureSession> connect_direct(
        const PublicKey& expected_pubkey,
        const TransportEndpoint& carrier_ep)
    {
        if (cfg_.verbose)
            printf("[client] Connecting via carrier %s\n",
                   carrier_ep.to_string().c_str());

        // Open TCP connection to the carrier endpoint (IP is ephemeral carrier only)
        auto stream = TcpStream::connect(carrier_ep, cfg_.connect_timeout_ms);

        // Run identity-authenticated handshake
        // Pass expected_pubkey → handshake will reject if server key doesn't match
        IdentityHandshake hs(identity_, HandshakeRole::INITIATOR, expected_pubkey);
        HandshakeResult result = hs.run(stream);

        if (cfg_.verbose)
            printf("[client] Handshake OK — server identity: %s\n",
                   result.peer_node_id.fingerprint().c_str());

        // Session is now established; IP is no longer relevant
        return std::make_unique<SecureSession>(std::move(stream), result);
    }

    // -----------------------------------------------------------------------
    // Higher-level RPC methods (use an established session)
    // -----------------------------------------------------------------------

    // PING: measures round-trip latency, returns RTT in ms
    static double ping(SecureSession& session) {
        static std::atomic<uint64_t> req_id_counter{1};
        uint64_t req_id = req_id_counter++;

        proto::PingPayload ping;
        ping.request_id   = req_id;
        ping.timestamp_ms = now_ms();

        uint64_t t0 = now_monotonic_ms();
        if (!session.send(proto::MsgType::PING, ping.serialize()))
            throw std::runtime_error("Failed to send PING");

        auto msg = session.recv(10000);
        uint64_t t1 = now_monotonic_ms();

        if (!msg) throw std::runtime_error("No PONG received");
        if (msg->type != proto::MsgType::PONG)
            throw std::runtime_error("Expected PONG, got " +
                                     std::to_string((uint8_t)msg->type));

        auto pong = proto::PingPayload::deserialize(msg->payload.data(),
                                                     msg->payload.size());
        if (pong.request_id != req_id)
            throw std::runtime_error("PONG request_id mismatch");

        return (double)(t1 - t0);
    }

    // ECHO: sends a message, returns the server's response
    static std::string echo(SecureSession& session, const std::string& message) {
        static std::atomic<uint64_t> req_id_counter{1};

        proto::EchoPayload req;
        req.request_id = req_id_counter++;
        req.message    = message;

        if (!session.send(proto::MsgType::ECHO_REQ, req.serialize()))
            throw std::runtime_error("Failed to send ECHO_REQ");

        auto msg = session.recv(10000);
        if (!msg) throw std::runtime_error("No ECHO_RESP received");
        if (msg->type == proto::MsgType::ERROR) {
            auto err = proto::ErrorPayload::deserialize(msg->payload.data(),
                                                         msg->payload.size());
            throw std::runtime_error("Server error: " + err.message);
        }
        if (msg->type != proto::MsgType::ECHO_RESP)
            throw std::runtime_error("Expected ECHO_RESP");

        auto resp = proto::EchoPayload::deserialize(msg->payload.data(),
                                                     msg->payload.size());
        return resp.message;
    }

    // PING convenience (connect + ping + close)
    double ping_node(const NodeId& target_id) {
        auto sess = connect_by_node_id(target_id);
        double rtt = ping(*sess);
        sess->close();
        return rtt;
    }

    std::string echo_node(const NodeId& target_id, const std::string& message) {
        auto sess = connect_by_node_id(target_id);
        std::string resp = echo(*sess, message);
        sess->close();
        return resp;
    }

private:
    ClientConfig cfg_;
    NodeIdentity identity_;
};

} // namespace idn
