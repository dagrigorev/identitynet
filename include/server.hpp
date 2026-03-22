#pragma once
// ============================================================================
// server.hpp — Identity Network server node
//
// Flow per connection:
//  1. Accept TCP connection (carrier-level, not trusted yet)
//  2. Run identity handshake (mutual auth, key exchange)
//  3. Verify peer identity against ACL — reject if denied
//  4. Send SESSION_ACK, enter encrypted application loop
//  5. Dispatch incoming messages to registered service handlers
// ============================================================================

#include "handshake.hpp"
#include "session.hpp"
#include "authz.hpp"
#include "discovery.hpp"
#include "keystore.hpp"
#include <functional>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <map>

namespace idn {

// ---------------------------------------------------------------------------
// ServerConfig
// ---------------------------------------------------------------------------
struct ServerConfig {
    std::string listen_host        = "0.0.0.0";
    uint16_t    listen_port        = 7701;
    std::string identity_key_path  = "server.key";
    std::string acl_path           = "";          // empty = allow all
    std::string discovery_endpoint = "127.0.0.1:7700";
    bool        register_on_start  = true;
    bool        verbose            = true;
};

// ---------------------------------------------------------------------------
// ServiceHandler: callback for a specific MsgType
// ---------------------------------------------------------------------------
using ServiceHandler = std::function<void(SecureSession&,
                                          const SecureSession::ReceivedMessage&)>;

// ---------------------------------------------------------------------------
// IdentityServer
// ---------------------------------------------------------------------------
class IdentityServer {
public:
    explicit IdentityServer(ServerConfig cfg)
        : cfg_(std::move(cfg)),
          identity_(KeyStore::load_or_generate(cfg_.identity_key_path)),
          policy_(cfg_.acl_path.empty()
                  ? AuthorizationPolicy::allow_all()
                  : AuthorizationPolicy::load_from_file(cfg_.acl_path)) {

        register_default_handlers();
    }

    // Register a handler for a specific message type
    void on(proto::MsgType type, ServiceHandler handler) {
        handlers_[type] = std::move(handler);
    }

    const NodeIdentity& identity() const { return identity_; }
    AuthorizationPolicy& policy()        { return policy_; }

    // Start listening, optionally register with discovery
    void start() {
        printf("[server] Identity: %s\n", identity_.display().c_str());
        printf("[server] NodeId:   %s\n", identity_.node_id().to_hex().c_str());
        printf("[server] PubKey:   %s\n", identity_.public_key().to_base64().c_str());

        if (cfg_.register_on_start && !cfg_.discovery_endpoint.empty()) {
            try {
                auto disc_ep = TransportEndpoint::from_string(cfg_.discovery_endpoint);
                DiscoveryClient disc(disc_ep);
                TransportEndpoint my_ep{cfg_.listen_host == "0.0.0.0"
                                        ? "127.0.0.1" : cfg_.listen_host,
                                        cfg_.listen_port};
                if (disc.register_node(identity_, my_ep)) {
                    printf("[server] Registered with discovery @ %s\n",
                           cfg_.discovery_endpoint.c_str());
                    // Start heartbeat thread
                    start_heartbeat(disc_ep);
                }
            } catch (const std::exception& e) {
                fprintf(stderr, "[server] Discovery registration failed: %s\n", e.what());
            }
        }

        TransportEndpoint listen_ep{cfg_.listen_host, cfg_.listen_port};
        listener_.emplace(TcpListener::bind(listen_ep));
        running_ = true;

        printf("[server] Listening on %s:%u\n", cfg_.listen_host.c_str(), cfg_.listen_port);
        if (policy_.is_open())
            printf("[server] ACL: open (allow all authenticated peers)\n");
        else
            printf("[server] ACL: allowlist (%zu peers)\n", policy_.allowed_count());

        accept_thread_ = std::thread([this]{ accept_loop(); });
    }

    void stop() {
        running_ = false;
        heartbeat_running_ = false;
        if (accept_thread_.joinable()) accept_thread_.join();
        if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
    }

    void join() {
        if (accept_thread_.joinable()) accept_thread_.join();
    }

private:
    ServerConfig        cfg_;
    NodeIdentity        identity_;
    AuthorizationPolicy policy_;
    std::optional<TcpListener> listener_;
    std::atomic<bool>   running_{false};
    std::thread         accept_thread_;

    std::atomic<bool>   heartbeat_running_{false};
    std::thread         heartbeat_thread_;

    std::map<proto::MsgType, ServiceHandler> handlers_;

    // -----------------------------------------------------------------------
    // Default built-in service handlers
    // -----------------------------------------------------------------------
    void register_default_handlers() {
        // PING → PONG
        on(proto::MsgType::PING, [this](SecureSession& sess,
                                         const SecureSession::ReceivedMessage& msg) {
            if (msg.payload.size() < 16) return;
            auto ping = proto::PingPayload::deserialize(msg.payload.data(),
                                                        msg.payload.size());
            if (cfg_.verbose)
                printf("[server] PING from %s (req_id=%llu)\n",
                       sess.peer_node_id().fingerprint().c_str(),
                       (unsigned long long)ping.request_id);

            // Pong reuses same payload to echo back request_id
            proto::PingPayload pong;
            pong.request_id   = ping.request_id;
            pong.timestamp_ms = now_ms();
            sess.send(proto::MsgType::PONG, pong.serialize());
        });

        // ECHO_REQ → ECHO_RESP
        on(proto::MsgType::ECHO_REQ, [this](SecureSession& sess,
                                              const SecureSession::ReceivedMessage& msg) {
            auto echo = proto::EchoPayload::deserialize(msg.payload.data(),
                                                         msg.payload.size());
            if (cfg_.verbose)
                printf("[server] ECHO from %s: \"%s\"\n",
                       sess.peer_node_id().fingerprint().c_str(),
                       echo.message.c_str());

            proto::EchoPayload resp;
            resp.request_id = echo.request_id;
            resp.message    = "[echo] " + echo.message
                            + " [from:" + sess.peer_node_id().fingerprint() + "]";
            sess.send(proto::MsgType::ECHO_RESP, resp.serialize());
        });
    }

    // -----------------------------------------------------------------------
    // Accept loop
    // -----------------------------------------------------------------------
    void accept_loop() {
        while (running_) {
            pollfd pfd{listener_->fd(), POLLIN, 0};
            if (poll(&pfd, 1, 500) <= 0) continue;

            try {
                auto [stream, peer_ep] = listener_->accept();

                if (cfg_.verbose)
                    printf("[server] TCP connection from %s (transport carrier)\n",
                           peer_ep.to_string().c_str());

                // Handle each peer in a dedicated thread
                auto* s = new TcpStream(std::move(stream));
                std::thread([this, s, peer_ep]() mutable {
                    handle_peer(*s, peer_ep);
                    delete s;
                }).detach();

            } catch (const std::exception& e) {
                if (running_)
                    fprintf(stderr, "[server] accept error: %s\n", e.what());
            }
        }
    }

    // -----------------------------------------------------------------------
    // Per-peer handler: handshake → ACL → session loop
    // -----------------------------------------------------------------------
    void handle_peer(TcpStream& stream, const TransportEndpoint& carrier_ep) {
        // Step 1: Run identity handshake (responder side)
        HandshakeResult handshake_result;
        try {
            IdentityHandshake hs(identity_, HandshakeRole::RESPONDER);
            handshake_result = hs.run(stream);
        } catch (const std::exception& e) {
            fprintf(stderr, "[server] Handshake failed from carrier %s: %s\n",
                    carrier_ep.to_string().c_str(), e.what());
            // Send rejection
            proto::ErrorPayload err;
            err.code    = proto::ErrorCode::AUTH_FAILED;
            err.message = "Handshake failed";
            stream.send_frame(proto::MsgType::AUTH_REJECT, err.serialize());
            return;
        }

        const NodeId& peer_id = handshake_result.peer_node_id;

        if (cfg_.verbose)
            printf("[server] Handshake OK — peer identity: %s\n",
                   peer_id.fingerprint().c_str());

        // Step 2: ACL check — identity-based, not IP-based
        if (!policy_.is_allowed(peer_id)) {
            printf("[server] ACL DENY: %s\n", peer_id.to_hex().c_str());
            proto::ErrorPayload err;
            err.code    = proto::ErrorCode::ACCESS_DENIED;
            err.message = "Access denied by policy";
            stream.send_frame(proto::MsgType::AUTH_REJECT, err.serialize());
            return;
        }

        printf("[server] ACL ALLOW: %s\n", peer_id.fingerprint().c_str());

        // Step 3: Send SESSION_ACK — encrypted session begins
        stream.send_frame(proto::MsgType::SESSION_ACK);

        // Step 4: Enter encrypted session loop
        SecureSession session(std::move(stream), handshake_result);

        printf("[server] Secure session established with %s\n",
               peer_id.fingerprint().c_str());

        while (!session.is_closed()) {
            auto msg = session.recv(60000);
            if (!msg) {
                if (cfg_.verbose)
                    printf("[server] Session closed: %s\n",
                           peer_id.fingerprint().c_str());
                break;
            }

            if (msg->type == proto::MsgType::GOODBYE) break;

            auto it = handlers_.find(msg->type);
            if (it != handlers_.end()) {
                try {
                    it->second(session, *msg);
                } catch (const std::exception& e) {
                    fprintf(stderr, "[server] Handler error: %s\n", e.what());
                    proto::ErrorPayload err;
                    err.code    = proto::ErrorCode::INTERNAL;
                    err.message = e.what();
                    session.send(proto::MsgType::ERROR, err.serialize());
                }
            } else {
                if (cfg_.verbose)
                    fprintf(stderr, "[server] Unknown msg type 0x%02x from %s\n",
                            (uint8_t)msg->type, peer_id.fingerprint().c_str());
            }
        }

        printf("[server] Session ended: %s | sent=%llu recv=%llu bytes\n",
               peer_id.fingerprint().c_str(),
               (unsigned long long)session.bytes_sent(),
               (unsigned long long)session.bytes_recv());
    }

    // -----------------------------------------------------------------------
    // Heartbeat thread
    // -----------------------------------------------------------------------
    void start_heartbeat(const TransportEndpoint& disc_ep) {
        heartbeat_running_ = true;
        heartbeat_thread_ = std::thread([this, disc_ep]() {
            while (heartbeat_running_) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                if (!heartbeat_running_) break;
                try {
                    DiscoveryClient disc(disc_ep);
                    disc.heartbeat(identity_.node_id());
                } catch (...) {}
            }
        });
    }
};

} // namespace idn
