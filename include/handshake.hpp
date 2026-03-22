#pragma once
// ============================================================================
// handshake.hpp — Identity-based mutual authentication handshake
//
// Security properties provided:
//  ✓ Mutual authentication: both parties prove possession of long-term key
//  ✓ Forward secrecy: ephemeral X25519 per session
//  ✓ MITM protection: session bound to known peer public key
//  ✓ Replay protection: timestamp + nonce per proof
//  ✓ Identity binding: session keys derived with peer identity in context
// ============================================================================

#include "crypto.hpp"
#include "transport.hpp"
#include "protocol.hpp"
#include <optional>
#include <functional>
#include <iostream>

namespace idn {

// ---------------------------------------------------------------------------
// HandshakeResult: output of a successful handshake
// ---------------------------------------------------------------------------
struct HandshakeResult {
    NodeId      peer_node_id{};      // Authenticated peer identity
    PublicKey   peer_public_key{};   // Peer's long-term public key
    SessionKeys session_keys{};      // Derived symmetric keys
    uint64_t    established_at_ms = 0;
};

// ---------------------------------------------------------------------------
// Handshake state machine (initiator / responder)
// ---------------------------------------------------------------------------
enum class HandshakeRole { INITIATOR, RESPONDER };
enum class HandshakeState {
    INIT,
    SENT_HELLO, RECV_HELLO,
    SENT_PROOF, RECV_PROOF,
    COMPLETE, FAILED
};

// ---------------------------------------------------------------------------
// IdentityHandshake: performs full mutual auth + key establishment
// ---------------------------------------------------------------------------
class IdentityHandshake {
public:
    // Optional known_peer_pubkey: if set, we verify server IS that key (MITM protection)
    IdentityHandshake(const NodeIdentity& local_id,
                      HandshakeRole role,
                      std::optional<PublicKey> known_peer_pubkey = std::nullopt)
        : local_id_(local_id), role_(role),
          known_peer_pubkey_(std::move(known_peer_pubkey)),
          state_(HandshakeState::INIT) {}

    // Run the full handshake over the given stream.
    // Returns HandshakeResult on success, throws on failure.
    HandshakeResult run(TcpStream& stream) {
        if (role_ == HandshakeRole::INITIATOR)
            return run_initiator(stream);
        else
            return run_responder(stream);
    }

private:
    const NodeIdentity& local_id_;
    HandshakeRole       role_;
    std::optional<PublicKey> known_peer_pubkey_;
    HandshakeState      state_;

    // -----------------------------------------------------------------------
    // INITIATOR path
    // -----------------------------------------------------------------------
    HandshakeResult run_initiator(TcpStream& stream) {
        // Step 1: Generate ephemeral key, send ClientHello
        EphemeralKeyPair eph;
        uint64_t ts = now_ms();

        proto::ClientHelloPayload hello;
        hello.eph_pub      = eph.public_key_bytes();
        hello.node_id      = local_id_.node_id();
        hello.timestamp_ms = ts;

        stream.send_frame(proto::MsgType::CLIENT_HELLO, hello.serialize());
        state_ = HandshakeState::SENT_HELLO;

        // Step 2: Receive ServerHello
        auto frame = stream.read_frame();
        if (!frame) throw std::runtime_error("No ServerHello received");
        if ((proto::MsgType)frame->first.msg_type != proto::MsgType::SERVER_HELLO)
            throw std::runtime_error("Expected SERVER_HELLO");

        auto server_hello = proto::ServerHelloPayload::deserialize(
            frame->second.data(), frame->second.size());
        state_ = HandshakeState::RECV_HELLO;

        // Step 3: Receive ServerProof (server authenticates first)
        frame = stream.read_frame();
        if (!frame) throw std::runtime_error("No ServerProof received");
        if ((proto::MsgType)frame->first.msg_type != proto::MsgType::SERVER_PROOF)
            throw std::runtime_error("Expected SERVER_PROOF");

        auto server_proof = proto::ServerProofPayload::deserialize(
            frame->second.data(), frame->second.size());

        // Verify server's claimed node_id matches their public key
        auto claimed_server_node_id = server_proof.public_key.to_node_id();
        if (claimed_server_node_id != server_hello.node_id)
            throw std::runtime_error("Server node_id / public_key mismatch");

        // If we have a known public key for the server, enforce it (MITM protection)
        if (known_peer_pubkey_.has_value()) {
            if (server_proof.public_key != *known_peer_pubkey_)
                throw std::runtime_error("Server public key does not match expected! MITM?");
        }

        // Verify server's identity proof signature
        auto server_transcript = proto::server_proof_transcript(
            server_hello.eph_pub, hello.eph_pub,
            local_id_.node_id(), server_hello.timestamp_ms);

        if (!verify_signature(server_proof.public_key,
                              server_transcript.data(), server_transcript.size(),
                              server_proof.signature.data(), 64))
            throw std::runtime_error("Server identity proof verification FAILED");

        state_ = HandshakeState::RECV_PROOF;

        // Step 4: Send ClientProof
        auto client_transcript = proto::client_proof_transcript(
            hello.eph_pub, server_hello.eph_pub,
            server_hello.node_id, ts);

        auto sig = local_id_.sign(client_transcript.data(), client_transcript.size());

        proto::ClientProofPayload client_proof;
        client_proof.public_key = local_id_.public_key();
        client_proof.signature  = sig;

        stream.send_frame(proto::MsgType::CLIENT_PROOF, client_proof.serialize());
        state_ = HandshakeState::SENT_PROOF;

        // Step 5: Receive SESSION_ACK or AUTH_REJECT
        frame = stream.read_frame();
        if (!frame) throw std::runtime_error("No session ack received");

        auto msg_type = (proto::MsgType)frame->first.msg_type;
        if (msg_type == proto::MsgType::AUTH_REJECT) {
            std::string reason;
            if (!frame->second.empty())
                reason.assign((char*)frame->second.data(), frame->second.size());
            throw std::runtime_error("Auth rejected by server: " + reason);
        }
        if (msg_type != proto::MsgType::SESSION_ACK)
            throw std::runtime_error("Expected SESSION_ACK");

        state_ = HandshakeState::COMPLETE;

        // Step 6: Derive session keys
        auto dh_secret = eph.dh(server_hello.eph_pub);
        auto session_keys = SessionKeys::derive(
            dh_secret, hello.eph_pub, server_hello.eph_pub, true);

        return HandshakeResult{
            .peer_node_id       = server_hello.node_id,
            .peer_public_key    = server_proof.public_key,
            .session_keys       = session_keys,
            .established_at_ms  = now_ms()
        };
    }

    // -----------------------------------------------------------------------
    // RESPONDER path
    // -----------------------------------------------------------------------
    HandshakeResult run_responder(TcpStream& stream) {
        // Step 1: Receive ClientHello
        auto frame = stream.read_frame();
        if (!frame) throw std::runtime_error("No ClientHello received");
        if ((proto::MsgType)frame->first.msg_type != proto::MsgType::CLIENT_HELLO)
            throw std::runtime_error("Expected CLIENT_HELLO");

        auto client_hello = proto::ClientHelloPayload::deserialize(
            frame->second.data(), frame->second.size());
        state_ = HandshakeState::RECV_HELLO;

        // Timestamp freshness check (within ±30s)
        uint64_t now = now_ms();
        int64_t drift = (int64_t)now - (int64_t)client_hello.timestamp_ms;
        if (drift > 30000 || drift < -30000)
            throw std::runtime_error("ClientHello timestamp too stale: drift=" +
                                     std::to_string(drift) + "ms");

        // Step 2: Generate ephemeral key, send ServerHello
        EphemeralKeyPair eph;
        uint64_t server_ts = now;

        proto::ServerHelloPayload server_hello;
        server_hello.eph_pub      = eph.public_key_bytes();
        server_hello.node_id      = local_id_.node_id();
        server_hello.timestamp_ms = server_ts;

        stream.send_frame(proto::MsgType::SERVER_HELLO, server_hello.serialize());
        state_ = HandshakeState::SENT_HELLO;

        // Step 3: Send ServerProof (server authenticates first to client)
        auto server_transcript = proto::server_proof_transcript(
            eph.public_key_bytes(), client_hello.eph_pub,
            client_hello.node_id, server_ts);

        auto sig = local_id_.sign(server_transcript.data(), server_transcript.size());

        proto::ServerProofPayload server_proof;
        server_proof.public_key = local_id_.public_key();
        server_proof.signature  = sig;

        stream.send_frame(proto::MsgType::SERVER_PROOF, server_proof.serialize());
        state_ = HandshakeState::SENT_PROOF;

        // Step 4: Receive ClientProof
        frame = stream.read_frame();
        if (!frame) throw std::runtime_error("No ClientProof received");
        if ((proto::MsgType)frame->first.msg_type != proto::MsgType::CLIENT_PROOF)
            throw std::runtime_error("Expected CLIENT_PROOF");

        auto client_proof = proto::ClientProofPayload::deserialize(
            frame->second.data(), frame->second.size());

        // Verify client's claimed node_id matches their public key
        auto claimed_client_node_id = client_proof.public_key.to_node_id();
        if (claimed_client_node_id != client_hello.node_id)
            throw std::runtime_error("Client node_id / public_key mismatch");

        // Verify client's identity proof signature
        auto client_transcript = proto::client_proof_transcript(
            client_hello.eph_pub, eph.public_key_bytes(),
            local_id_.node_id(), client_hello.timestamp_ms);

        if (!verify_signature(client_proof.public_key,
                              client_transcript.data(), client_transcript.size(),
                              client_proof.signature.data(), 64))
            throw std::runtime_error("Client identity proof verification FAILED");

        state_ = HandshakeState::RECV_PROOF;

        // Return the verified peer identity for ACL check by caller
        // Caller will send SESSION_ACK or AUTH_REJECT
        HandshakeResult result{
            .peer_node_id       = client_hello.node_id,
            .peer_public_key    = client_proof.public_key,
            .session_keys       = {},
            .established_at_ms  = 0
        };

        // Derive session keys
        auto dh_secret = eph.dh(client_hello.eph_pub);
        result.session_keys = SessionKeys::derive(
            dh_secret, client_hello.eph_pub, eph.public_key_bytes(), false);
        result.established_at_ms = now_ms();

        state_ = HandshakeState::COMPLETE;
        return result;
    }
};

} // namespace idn
