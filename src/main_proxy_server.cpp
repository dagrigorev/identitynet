// ============================================================================
// main_proxy_server.cpp — Identity Network Proxy Server (runs on VPS)
//
// Accepts IdentityNet connections from authenticated clients.
// For each PROXY_CONNECT message, opens a real TCP connection to the
// requested host:port, then forwards data bidirectionally.
//
// Architecture:
//   [Browser] → SOCKS5 → [proxy_client] ═══ IdentityNet ═══ [proxy_server] → [Internet]
//                                        Ed25519+AES256-GCM
//
// Usage:
//   identitynet-proxy-server init   [--key PATH]
//   identitynet-proxy-server run    [--key PATH] [--port PORT]
//                                   [--discovery EP] [--acl PATH]
// ============================================================================

#include "server.hpp"
#include "proxy_proto.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <csignal>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>

// ---------------------------------------------------------------------------
// ProxyStream: one active outbound TCP connection to a real host
// ---------------------------------------------------------------------------
struct ProxyStream {
    int      fd        = -1;
    uint32_t stream_id = 0;
    std::atomic<bool> closed{false};

    ~ProxyStream() {
        if (fd >= 0) { ::shutdown(fd, SHUT_RDWR); ::close(fd); }
    }
};

// ---------------------------------------------------------------------------
// ProxySessionHandler: manages all streams for one client IdentityNet session
// ---------------------------------------------------------------------------
class ProxySessionHandler {
public:
    explicit ProxySessionHandler(idn::SecureSession& sess) : sess_(sess) {}

    void run() {
        printf("[proxy-server] New proxy session from: %s\n",
               sess_.peer_node_id().fingerprint().c_str());

        while (!sess_.is_closed()) {
            auto msg = sess_.recv(60000);
            if (!msg) break;

            switch (msg->type) {
            case idn::proto::MsgType::PROXY_CONNECT:
                handle_connect(msg->payload);
                break;
            case idn::proto::MsgType::PROXY_DATA:
                handle_data(msg->payload);
                break;
            case idn::proto::MsgType::PROXY_CLOSE:
                handle_close(msg->payload);
                break;
            case idn::proto::MsgType::PING: {
                idn::proto::PingPayload p = idn::proto::PingPayload::deserialize(
                    msg->payload.data(), msg->payload.size());
                p.timestamp_ms = idn::now_ms();
                sess_.send(idn::proto::MsgType::PONG, p.serialize());
                break;
            }
            case idn::proto::MsgType::GOODBYE:
                goto done;
            default:
                break;
            }
        }
        done:
        close_all_streams();
        printf("[proxy-server] Session ended: %s\n",
               sess_.peer_node_id().fingerprint().c_str());
    }

private:
    idn::SecureSession& sess_;
    std::map<uint32_t, std::shared_ptr<ProxyStream>> streams_;
    std::mutex streams_mu_;

    // ── Connect to real host ────────────────────────────────────────────────
    void handle_connect(const std::vector<uint8_t>& payload) {
        auto req = idn::proxy::ConnectPayload::deserialize(
            payload.data(), payload.size());

        printf("[proxy-server] CONNECT stream=%u → %s:%u\n",
               req.stream_id, req.host.c_str(), req.port);

        // Resolve hostname
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        std::string port_str = std::to_string(req.port);

        int r = getaddrinfo(req.host.c_str(), port_str.c_str(), &hints, &res);
        if (r != 0) {
            send_error(req.stream_id,
                       std::string("DNS failed: ") + gai_strerror(r));
            return;
        }

        // Connect
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { freeaddrinfo(res); send_error(req.stream_id, "socket() failed"); return; }

        // Non-blocking connect with 10s timeout
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        ::connect(fd, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);

        pollfd pfd{fd, POLLOUT, 0};
        if (poll(&pfd, 1, 10000) <= 0) {
            ::close(fd);
            send_error(req.stream_id, "connect timeout");
            return;
        }
        int err = 0; socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err != 0) {
            ::close(fd);
            send_error(req.stream_id, std::string("connect failed: ") + strerror(err));
            return;
        }
        fcntl(fd, F_SETFL, flags); // restore blocking

        // Register stream
        auto stream = std::make_shared<ProxyStream>();
        stream->fd        = fd;
        stream->stream_id = req.stream_id;
        {
            std::lock_guard<std::mutex> lk(streams_mu_);
            streams_[req.stream_id] = stream;
        }

        // Send PROXY_CONNECTED
        idn::proxy::ConnectedPayload ok;
        ok.stream_id = req.stream_id;
        sess_.send(idn::proto::MsgType::PROXY_CONNECTED, ok.serialize());

        printf("[proxy-server] stream=%u connected to %s:%u\n",
               req.stream_id, req.host.c_str(), req.port);

        // Start reader thread: remote host → IdentityNet client
        std::thread([this, stream]() {
            read_loop(stream);
        }).detach();
    }

    // ── Forward data from client → real host ───────────────────────────────
    void handle_data(const std::vector<uint8_t>& payload) {
        auto d = idn::proxy::DataPayload::deserialize(payload.data(), payload.size());

        std::shared_ptr<ProxyStream> stream;
        {
            std::lock_guard<std::mutex> lk(streams_mu_);
            auto it = streams_.find(d.stream_id);
            if (it == streams_.end()) return;
            stream = it->second;
        }

        if (stream->closed || d.data.empty()) return;

        // Write all to real host
        size_t sent = 0;
        while (sent < d.data.size()) {
            ssize_t r = ::send(stream->fd,
                               d.data.data() + sent,
                               d.data.size() - sent,
                               MSG_NOSIGNAL);
            if (r <= 0) {
                close_stream(d.stream_id);
                return;
            }
            sent += r;
        }
    }

    // ── Client wants to close a stream ─────────────────────────────────────
    void handle_close(const std::vector<uint8_t>& payload) {
        auto c = idn::proxy::ClosePayload::deserialize(payload.data(), payload.size());
        close_stream(c.stream_id);
    }

    // ── Read loop: real host → IdentityNet client ──────────────────────────
    void read_loop(std::shared_ptr<ProxyStream> stream) {
        uint8_t buf[32768];
        while (!stream->closed && !sess_.is_closed()) {
            pollfd pfd{stream->fd, POLLIN, 0};
            if (poll(&pfd, 1, 5000) <= 0) {
                if (sess_.is_closed()) break;
                continue;
            }

            ssize_t n = ::recv(stream->fd, buf, sizeof(buf), 0);
            if (n <= 0) {
                // Remote host closed connection
                if (!stream->closed.exchange(true)) {
                    idn::proxy::ClosePayload cl{stream->stream_id};
                    sess_.send(idn::proto::MsgType::PROXY_CLOSE, cl.serialize());
                }
                break;
            }

            idn::proxy::DataPayload d;
            d.stream_id = stream->stream_id;
            d.data.assign(buf, buf + n);
            sess_.send(idn::proto::MsgType::PROXY_DATA, d.serialize());
        }

        std::lock_guard<std::mutex> lk(streams_mu_);
        streams_.erase(stream->stream_id);
    }

    // ── Helpers ────────────────────────────────────────────────────────────
    void send_error(uint32_t stream_id, const std::string& msg) {
        fprintf(stderr, "[proxy-server] stream=%u error: %s\n", stream_id, msg.c_str());
        idn::proxy::ErrorPayload e;
        e.stream_id = stream_id;
        e.message   = msg;
        sess_.send(idn::proto::MsgType::PROXY_ERROR, e.serialize());
    }

    void close_stream(uint32_t stream_id) {
        std::lock_guard<std::mutex> lk(streams_mu_);
        auto it = streams_.find(stream_id);
        if (it != streams_.end()) {
            it->second->closed = true;
            streams_.erase(it);
        }
    }

    void close_all_streams() {
        std::lock_guard<std::mutex> lk(streams_mu_);
        streams_.clear();
    }
};

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
static std::atomic<bool> g_stop{false};
static void sig_handler(int) { g_stop = true; }

static void cmd_init(int argc, char* argv[]) {
    std::string key_path = "proxy_server.key";
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--key" || a == "-k") && i+1 < argc) key_path = argv[++i];
    }
    auto id = idn::KeyStore::load_or_generate(key_path);
    idn::KeyStore::save_public(id, key_path + ".pub");
    printf("[proxy-server] Identity initialized.\n\n");
    idn::KeyStore::print_identity(id);
    printf("\n[proxy-server] Share this PUBLIC KEY with clients:\n");
    printf("  %s\n", id.public_key().to_base64().c_str());
    printf("\nClients connect using:\n");
    printf("  identitynet-proxy-client run --pubkey %s --proxy-port 1080\n",
           id.public_key().to_base64().c_str());
}

static void cmd_run(int argc, char* argv[]) {
    idn::ServerConfig cfg;
    cfg.identity_key_path  = "proxy_server.key";
    cfg.listen_port        = 7701;
    cfg.discovery_endpoint = "127.0.0.1:7700";
    cfg.register_on_start  = false;
    cfg.verbose            = false;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--key"  || a == "-k") && i+1 < argc) cfg.identity_key_path  = argv[++i];
        if ((a == "--port" || a == "-p") && i+1 < argc) cfg.listen_port        = (uint16_t)std::stoi(argv[++i]);
        if ((a == "--discovery" || a == "-d") && i+1 < argc) {
            cfg.discovery_endpoint = argv[++i];
            cfg.register_on_start  = true;
        }
        if ((a == "--acl") && i+1 < argc)  cfg.acl_path           = argv[++i];
        if (a == "--allow-all")             cfg.acl_path           = "";
        if (a == "--verbose")               cfg.verbose            = true;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   Identity Network — Proxy Server (VPS)      ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    idn::IdentityServer server(cfg);

    // Register proxy tunnel handler
    server.on(idn::proto::MsgType::PROXY_CONNECT,
        [](idn::SecureSession& sess,
           const idn::SecureSession::ReceivedMessage& first_msg)
        {
            // Hand off to per-session handler that also reads subsequent messages
            // We need to handle the full session, so spawn a handler
            ProxySessionHandler handler(sess);
            // Re-inject the first message by processing it directly
            handler.run();  // this won't work as written — see note below
            (void)first_msg;
        });

    // Actually: override with a full-session approach
    // The server's message loop calls handlers per-message, but proxy needs
    // to own the session loop. We use APP_DATA as a "take over" signal.
    // Better: register a special handler that replaces the server loop.
    // The cleanest way: register PROXY_CONNECT and have it spawn a thread
    // that takes over the session's recv loop.

    // We'll do it properly: create the server with a custom accept callback
    // by subclassing or using the raw handshake.
    // For simplicity: run a custom accept loop alongside the server.

    // Actually the simplest correct approach: don't use IdentityServer's
    // message dispatcher at all — run our own accept loop with raw handshake.
    server.stop(); // stop the auto-started server

    // Raw accept loop with proxy session handler
    idn::AuthorizationPolicy policy = cfg.acl_path.empty()
        ? idn::AuthorizationPolicy::allow_all()
        : idn::AuthorizationPolicy::load_from_file(cfg.acl_path);

    idn::NodeIdentity identity = idn::KeyStore::load_or_generate(cfg.identity_key_path);

    printf("[proxy-server] Node ID:  %s\n", identity.node_id().to_hex().c_str());
    printf("[proxy-server] PubKey:   %s\n", identity.public_key().to_base64().c_str());
    printf("[proxy-server] Listen:   0.0.0.0:%u\n", cfg.listen_port);
    if (policy.is_open())
        printf("[proxy-server] ACL:      open (allow all authenticated clients)\n");
    else
        printf("[proxy-server] ACL:      allowlist (%zu peers)\n", policy.allowed_count());
    printf("\nReady. Waiting for proxy clients...\n\n");

    // Register with discovery if configured
    if (cfg.register_on_start && !cfg.discovery_endpoint.empty()) {
        try {
            auto disc_ep = idn::TransportEndpoint::from_string(cfg.discovery_endpoint);
            idn::DiscoveryClient disc(disc_ep);
            idn::TransportEndpoint my_ep{"127.0.0.1", cfg.listen_port};
            disc.register_node(identity, my_ep);
            printf("[proxy-server] Registered with discovery @ %s\n\n",
                   cfg.discovery_endpoint.c_str());
        } catch (const std::exception& e) {
            fprintf(stderr, "[proxy-server] Discovery registration failed: %s\n", e.what());
        }
    }

    idn::TcpListener listener = idn::TcpListener::bind(
        {"0.0.0.0", cfg.listen_port});

    while (!g_stop) {
        pollfd pfd{listener.fd(), POLLIN, 0};
        if (poll(&pfd, 1, 500) <= 0) continue;

        try {
            auto [stream, carrier_ep] = listener.accept();

            std::thread([&identity, &policy, s = std::move(stream),
                         carrier_ep]() mutable
            {
                // Handshake
                idn::HandshakeResult result;
                try {
                    idn::IdentityHandshake hs(identity, idn::HandshakeRole::RESPONDER);
                    result = hs.run(s);
                } catch (const std::exception& e) {
                    fprintf(stderr, "[proxy-server] Handshake failed from %s: %s\n",
                            carrier_ep.to_string().c_str(), e.what());
                    return;
                }

                // ACL check
                if (!policy.is_allowed(result.peer_node_id)) {
                    printf("[proxy-server] ACL DENY: %s\n",
                           result.peer_node_id.fingerprint().c_str());
                    idn::proto::ErrorPayload err;
                    err.code    = idn::proto::ErrorCode::ACCESS_DENIED;
                    err.message = "Access denied";
                    s.send_frame(idn::proto::MsgType::AUTH_REJECT, err.serialize());
                    return;
                }

                printf("[proxy-server] Client connected: %s\n",
                       result.peer_node_id.fingerprint().c_str());

                s.send_frame(idn::proto::MsgType::SESSION_ACK);

                idn::SecureSession sess(std::move(s), result);
                ProxySessionHandler handler(sess);
                handler.run();
            }).detach();

        } catch (const std::exception& e) {
            if (!g_stop)
                fprintf(stderr, "[proxy-server] accept error: %s\n", e.what());
        }
    }

    printf("[proxy-server] Stopped.\n");
}

static void print_usage(const char* prog) {
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  init   Generate server identity and show public key\n");
    printf("  run    Start proxy server\n\n");
    printf("Options for 'run':\n");
    printf("  --key PATH        Identity key file (default: proxy_server.key)\n");
    printf("  --port PORT       Listen port (default: 7701)\n");
    printf("  --acl PATH        ACL file (default: allow all)\n");
    printf("  --discovery EP    Register with discovery server\n");
    printf("  --allow-all       Accept all authenticated clients\n");
    printf("  --verbose         Verbose output\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }
    std::string cmd = argv[1];
    if      (cmd == "init") cmd_init(argc, argv);
    else if (cmd == "run")  cmd_run(argc, argv);
    else { print_usage(argv[0]); return 1; }
    return 0;
}
