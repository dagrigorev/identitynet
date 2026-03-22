// ============================================================================
// main_proxy_client.cpp — Identity Network Proxy Client
//
// Runs locally (Windows via Docker or Linux).
// Listens as SOCKS5 proxy on localhost:1080 (configurable).
// For each browser TCP connection:
//   1. Accepts SOCKS5 handshake
//   2. Extracts target host:port
//   3. Sends PROXY_CONNECT over IdentityNet tunnel to VPS
//   4. Relays data bidirectionally through the encrypted tunnel
//
// Browser setup:
//   Firefox: Settings → Network → Manual proxy → SOCKS5 Host: 127.0.0.1 Port: 1080
//   Chrome:  --proxy-server="socks5://127.0.0.1:1080"
//   System:  Windows Settings → Proxy → Manual → SOCKS 127.0.0.1:1080
//
// Usage:
//   identitynet-proxy-client init  [--key PATH]
//   identitynet-proxy-client run   --pubkey SERVER_PUBKEY
//                                  [--key PATH] [--proxy-port PORT]
//                                  [--server-host HOST] [--server-port PORT]
//                                  [--discovery EP]
// ============================================================================

#include "client.hpp"
#include "proxy_proto.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <csignal>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>

// ---------------------------------------------------------------------------
// SOCKS5 protocol constants (RFC 1928)
// ---------------------------------------------------------------------------
static constexpr uint8_t SOCKS5_VER        = 0x05;
static constexpr uint8_t SOCKS5_AUTH_NONE  = 0x00;
static constexpr uint8_t SOCKS5_CMD_CONNECT= 0x01;
static constexpr uint8_t SOCKS5_ATYP_IPV4  = 0x01;
static constexpr uint8_t SOCKS5_ATYP_DOMAIN= 0x03;
static constexpr uint8_t SOCKS5_ATYP_IPV6  = 0x04;
static constexpr uint8_t SOCKS5_REP_OK     = 0x00;
static constexpr uint8_t SOCKS5_REP_FAIL   = 0x01;
static constexpr uint8_t SOCKS5_REP_NOCONN = 0x05;

// ---------------------------------------------------------------------------
// Helpers: read/write exactly N bytes on a plain fd
// ---------------------------------------------------------------------------
static bool fd_read_exact(int fd, uint8_t* buf, size_t n, int timeout_ms = 10000) {
    size_t got = 0;
    while (got < n) {
        pollfd pfd{fd, POLLIN, 0};
        if (poll(&pfd, 1, timeout_ms) <= 0) return false;
        ssize_t r = ::recv(fd, buf + got, n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

static bool fd_write_all(int fd, const uint8_t* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = ::send(fd, buf + sent, n - sent, MSG_NOSIGNAL);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Parse SOCKS5 handshake, return {host, port} or throw
// ---------------------------------------------------------------------------
static std::pair<std::string, uint16_t> socks5_handshake(int fd) {
    // Step 1: Version + method selection
    uint8_t buf[512];
    if (!fd_read_exact(fd, buf, 2)) throw std::runtime_error("socks5: no greeting");
    if (buf[0] != SOCKS5_VER) throw std::runtime_error("socks5: wrong version");
    uint8_t nmethods = buf[1];
    if (!fd_read_exact(fd, buf, nmethods)) throw std::runtime_error("socks5: no methods");
    // Accept no-auth (0x00)
    uint8_t reply[2] = {SOCKS5_VER, SOCKS5_AUTH_NONE};
    fd_write_all(fd, reply, 2);

    // Step 2: Request
    if (!fd_read_exact(fd, buf, 4)) throw std::runtime_error("socks5: no request");
    if (buf[0] != SOCKS5_VER) throw std::runtime_error("socks5: bad request version");
    if (buf[1] != SOCKS5_CMD_CONNECT) {
        // Only CONNECT supported
        uint8_t err[10] = {SOCKS5_VER, 0x07, 0x00, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0};
        fd_write_all(fd, err, 10);
        throw std::runtime_error("socks5: unsupported command");
    }
    // buf[2] = reserved, buf[3] = atyp
    std::string host;
    uint16_t    port;

    uint8_t atyp = buf[3];
    if (atyp == SOCKS5_ATYP_IPV4) {
        uint8_t ip[4];
        if (!fd_read_exact(fd, ip, 4)) throw std::runtime_error("socks5: no ipv4");
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ip, ipstr, sizeof(ipstr));
        host = ipstr;
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        uint8_t dlen;
        if (!fd_read_exact(fd, &dlen, 1)) throw std::runtime_error("socks5: no dlen");
        if (!fd_read_exact(fd, buf, dlen)) throw std::runtime_error("socks5: no domain");
        host.assign((char*)buf, dlen);
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        // IPv6 not supported — tell client
        uint8_t err[10] = {SOCKS5_VER, SOCKS5_REP_NOCONN, 0x00,
                           SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0};
        fd_write_all(fd, err, 10);
        throw std::runtime_error("socks5: IPv6 not supported");
    } else {
        throw std::runtime_error("socks5: unknown atyp");
    }

    uint8_t port_bytes[2];
    if (!fd_read_exact(fd, port_bytes, 2)) throw std::runtime_error("socks5: no port");
    port = ((uint16_t)port_bytes[0] << 8) | port_bytes[1];

    return {host, port};
}

static void socks5_send_reply(int fd, bool ok) {
    uint8_t rep[10] = {
        SOCKS5_VER,
        (uint8_t)(ok ? SOCKS5_REP_OK : SOCKS5_REP_FAIL),
        0x00,
        SOCKS5_ATYP_IPV4,
        0, 0, 0, 0,   // bound address
        0, 0           // bound port
    };
    fd_write_all(fd, rep, 10);
}

// ---------------------------------------------------------------------------
// TunnelSession: manages the IdentityNet session + all SOCKS5 streams
// ---------------------------------------------------------------------------
class TunnelSession {
public:
    TunnelSession(std::unique_ptr<idn::SecureSession> sess)
        : sess_(std::move(sess)), stream_id_counter_(1)
    {
        printf("[proxy-client] Tunnel established to: %s\n",
               sess_->peer_node_id().fingerprint().c_str());
        // Start the reader thread that demultiplexes inbound proxy messages
        reader_thread_ = std::thread([this]{ inbound_loop(); });
    }

    ~TunnelSession() {
        sess_->close();
        if (reader_thread_.joinable()) reader_thread_.join();
    }

    // Handle one browser connection (called in its own thread)
    void handle_browser_connection(int browser_fd) {
        std::string host;
        uint16_t    port;

        try {
            auto [h, p] = socks5_handshake(browser_fd);
            host = h; port = p;
        } catch (const std::exception& e) {
            fprintf(stderr, "[proxy-client] SOCKS5 error: %s\n", e.what());
            ::close(browser_fd);
            return;
        }

        printf("[proxy-client] → %s:%u\n", host.c_str(), port);

        uint32_t sid = stream_id_counter_++;

        // Register a pending stream
        auto pending = std::make_shared<PendingStream>();
        {
            std::lock_guard<std::mutex> lk(streams_mu_);
            pending_[sid] = pending;
        }

        // Send PROXY_CONNECT over tunnel
        idn::proxy::ConnectPayload conn;
        conn.stream_id = sid;
        conn.host      = host;
        conn.port      = port;
        if (!sess_->send(idn::proto::MsgType::PROXY_CONNECT, conn.serialize())) {
            socks5_send_reply(browser_fd, false);
            ::close(browser_fd);
            return;
        }

        // Wait for PROXY_CONNECTED or PROXY_ERROR (up to 15s)
        bool connected = false;
        {
            std::unique_lock<std::mutex> lk(pending->mu);
            connected = pending->cv.wait_for(lk, std::chrono::seconds(15),
                [&]{ return pending->resolved; });
        }

        if (!connected || !pending->success) {
            socks5_send_reply(browser_fd, false);
            ::close(browser_fd);
            {
                std::lock_guard<std::mutex> lk(streams_mu_);
                pending_.erase(sid);
            }
            return;
        }

        // Connection established — tell browser
        socks5_send_reply(browser_fd, true);

        // Register active stream
        auto stream = std::make_shared<ActiveStream>();
        stream->browser_fd = browser_fd;
        stream->stream_id  = sid;
        {
            std::lock_guard<std::mutex> lk(streams_mu_);
            pending_.erase(sid);
            active_[sid] = stream;
        }

        // Start browser→tunnel relay (this thread)
        browser_to_tunnel(stream);
    }

    bool is_alive() const { return !sess_->is_closed(); }

private:
    struct PendingStream {
        std::mutex              mu;
        std::condition_variable cv;
        bool resolved = false;
        bool success  = false;
    };

    struct ActiveStream {
        int      browser_fd = -1;
        uint32_t stream_id  = 0;
        std::atomic<bool> closed{false};

        ~ActiveStream() {
            if (browser_fd >= 0) {
                ::shutdown(browser_fd, SHUT_RDWR);
                ::close(browser_fd);
            }
        }
    };

    std::unique_ptr<idn::SecureSession>          sess_;
    std::atomic<uint32_t>                        stream_id_counter_;
    std::mutex                                   streams_mu_;
    std::map<uint32_t, std::shared_ptr<PendingStream>>  pending_;
    std::map<uint32_t, std::shared_ptr<ActiveStream>>   active_;
    std::thread                                  reader_thread_;

    // ── Inbound loop: tunnel → browser ─────────────────────────────────────
    void inbound_loop() {
        while (!sess_->is_closed()) {
            auto msg = sess_->recv(60000);
            if (!msg) break;

            switch (msg->type) {

            case idn::proto::MsgType::PROXY_CONNECTED: {
                auto c = idn::proxy::ConnectedPayload::deserialize(
                    msg->payload.data(), msg->payload.size());
                std::lock_guard<std::mutex> lk(streams_mu_);
                auto it = pending_.find(c.stream_id);
                if (it != pending_.end()) {
                    std::lock_guard<std::mutex> plk(it->second->mu);
                    it->second->success  = true;
                    it->second->resolved = true;
                    it->second->cv.notify_one();
                }
                break;
            }

            case idn::proto::MsgType::PROXY_ERROR: {
                auto e = idn::proxy::ErrorPayload::deserialize(
                    msg->payload.data(), msg->payload.size());
                fprintf(stderr, "[proxy-client] stream=%u error: %s\n",
                        e.stream_id, e.message.c_str());
                std::lock_guard<std::mutex> lk(streams_mu_);
                auto it = pending_.find(e.stream_id);
                if (it != pending_.end()) {
                    std::lock_guard<std::mutex> plk(it->second->mu);
                    it->second->success  = false;
                    it->second->resolved = true;
                    it->second->cv.notify_one();
                }
                break;
            }

            case idn::proto::MsgType::PROXY_DATA: {
                auto d = idn::proxy::DataPayload::deserialize(
                    msg->payload.data(), msg->payload.size());
                std::shared_ptr<ActiveStream> stream;
                {
                    std::lock_guard<std::mutex> lk(streams_mu_);
                    auto it = active_.find(d.stream_id);
                    if (it == active_.end() || d.data.empty()) break;
                    stream = it->second;
                }
                if (!stream->closed)
                    fd_write_all(stream->browser_fd,
                                 d.data.data(), d.data.size());
                break;
            }

            case idn::proto::MsgType::PROXY_CLOSE: {
                auto c = idn::proxy::ClosePayload::deserialize(
                    msg->payload.data(), msg->payload.size());
                std::lock_guard<std::mutex> lk(streams_mu_);
                auto it = active_.find(c.stream_id);
                if (it != active_.end()) {
                    it->second->closed = true;
                    active_.erase(it);
                }
                break;
            }

            case idn::proto::MsgType::GOODBYE:
                return;

            default:
                break;
            }
        }
    }

    // ── Browser → tunnel relay ──────────────────────────────────────────────
    void browser_to_tunnel(std::shared_ptr<ActiveStream> stream) {
        uint8_t buf[32768];
        while (!stream->closed && !sess_->is_closed()) {
            pollfd pfd{stream->browser_fd, POLLIN, 0};
            if (poll(&pfd, 1, 5000) <= 0) {
                if (sess_->is_closed()) break;
                continue;
            }

            ssize_t n = ::recv(stream->browser_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;

            idn::proxy::DataPayload d;
            d.stream_id = stream->stream_id;
            d.data.assign(buf, buf + n);
            if (!sess_->send(idn::proto::MsgType::PROXY_DATA, d.serialize())) break;
        }

        // Browser closed — tell server
        if (!stream->closed.exchange(true)) {
            idn::proxy::ClosePayload cl{stream->stream_id};
            sess_->send(idn::proto::MsgType::PROXY_CLOSE, cl.serialize());
        }

        std::lock_guard<std::mutex> lk(streams_mu_);
        active_.erase(stream->stream_id);
    }
};

// ---------------------------------------------------------------------------
// SOCKS5 listener
// ---------------------------------------------------------------------------
static std::atomic<bool> g_stop{false};
static void sig_handler(int) { g_stop = true; }

static void cmd_init(int argc, char* argv[]) {
    std::string key_path = "proxy_client.key";
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--key" || a == "-k") && i+1 < argc) key_path = argv[++i];
    }
    auto id = idn::KeyStore::load_or_generate(key_path);
    printf("[proxy-client] Identity initialized.\n\n");
    idn::KeyStore::print_identity(id);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <init|run> [options]\n\n", argv[0]);
        fprintf(stderr, "  init  Generate client identity\n");
        fprintf(stderr, "  run   Start SOCKS5 proxy\n\n");
        fprintf(stderr, "Options for 'run':\n");
        fprintf(stderr, "  --pubkey B64       Server public key (required)\n");
        fprintf(stderr, "  --node NODEID      Or server node_id (requires --discovery)\n");
        fprintf(stderr, "  --key PATH         Client key file (default: proxy_client.key)\n");
        fprintf(stderr, "  --server-host IP   VPS IP (for direct connect, no discovery)\n");
        fprintf(stderr, "  --server-port PORT VPS port (default: 7701)\n");
        fprintf(stderr, "  --proxy-port PORT  Local SOCKS5 port (default: 1080)\n");
        fprintf(stderr, "  --discovery EP     Discovery server endpoint\n");
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "init") { cmd_init(argc, argv); return 0; }
    if (cmd != "run")  {
        fprintf(stderr, "Unknown command: %s\n", cmd.c_str());
        return 1;
    }

    // Parse args
    std::string key_path          = "proxy_client.key";
    std::string server_pubkey_b64;
    std::string server_node_id_hex;
    std::string server_host       = "";
    uint16_t    server_port       = 7701;
    uint16_t    proxy_port        = 1080;
    std::string discovery_ep      = "";

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--key")           && i+1 < argc) key_path           = argv[++i];
        if ((a == "--pubkey")        && i+1 < argc) server_pubkey_b64  = argv[++i];
        if ((a == "--node")          && i+1 < argc) server_node_id_hex = argv[++i];
        if ((a == "--server-host")   && i+1 < argc) server_host         = argv[++i];
        if ((a == "--server-port")   && i+1 < argc) server_port         = (uint16_t)std::stoi(argv[++i]);
        if ((a == "--proxy-port")    && i+1 < argc) proxy_port          = (uint16_t)std::stoi(argv[++i]);
        if ((a == "--discovery" || a == "-d") && i+1 < argc) discovery_ep = argv[++i];
    }

    if (server_pubkey_b64.empty() && server_node_id_hex.empty()) {
        fprintf(stderr, "Error: --pubkey or --node required\n");
        return 1;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   Identity Network — Proxy Client            ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    // Setup client
    idn::ClientConfig cli_cfg;
    cli_cfg.identity_key_path  = key_path;
    cli_cfg.discovery_endpoint = discovery_ep.empty() ? "127.0.0.1:7700" : discovery_ep;
    cli_cfg.verbose            = false;
    idn::IdentityClient idnclient(cli_cfg);

    printf("[proxy-client] Client identity: %s\n",
           idnclient.identity().node_id().fingerprint().c_str());
    printf("[proxy-client] Connecting to proxy server...\n");

    // Connect to proxy server
    std::unique_ptr<idn::SecureSession> sess;
    try {
        if (!server_pubkey_b64.empty()) {
            auto pk = idn::PublicKey::from_base64(server_pubkey_b64);
            if (!server_host.empty()) {
                sess = idnclient.connect_direct(pk, {server_host, server_port});
            } else {
                sess = idnclient.connect_by_pubkey(pk);
            }
        } else {
            auto nid = idn::NodeId::from_hex(server_node_id_hex);
            sess = idnclient.connect_by_node_id(nid);
        }
    } catch (const std::exception& e) {
        fprintf(stderr, "\n[proxy-client] Connection failed: %s\n\n", e.what());
        fprintf(stderr, "Check:\n");
        fprintf(stderr, "  1. VPS is reachable: ping %s\n",
                server_host.empty() ? "<vps-ip>" : server_host.c_str());
        fprintf(stderr, "  2. Proxy server is running on port %u\n", server_port);
        fprintf(stderr, "  3. Firewall allows port %u\n", server_port);
        return 1;
    }

    printf("[proxy-client] ✓ Tunnel to %s established\n",
           sess->peer_node_id().fingerprint().c_str());
    printf("[proxy-client] Transport: AES-256-GCM over Ed25519-authenticated channel\n\n");

    TunnelSession tunnel(std::move(sess));

    // Raw SOCKS5 listener (using plain accept, not TcpStream)
    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(proxy_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[proxy-client] bind() failed on port %u: %s\n",
                proxy_port, strerror(errno));
        fprintf(stderr, "Try a different port: --proxy-port 1081\n");
        return 1;
    }
    ::listen(listen_fd, 128);

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  SOCKS5 proxy ready on 127.0.0.1:%-5u       ║\n", proxy_port);
    printf("╚══════════════════════════════════════════════╝\n\n");
    printf("Configure your browser:\n");
    printf("  Firefox:  Settings → General → Network Settings\n");
    printf("            → Manual proxy configuration → SOCKS Host\n");
    printf("            Host: 127.0.0.1   Port: %u   Version: SOCKS v5\n", proxy_port);
    printf("            ☑ Proxy DNS over SOCKS5 (important!)\n\n");
    printf("  Chrome:   chrome --proxy-server=\"socks5://127.0.0.1:%u\"\n\n", proxy_port);
    printf("  Test:     curl --socks5-hostname 127.0.0.1:%u https://ifconfig.me\n", proxy_port);
    printf("            (should show your VPS IP, not your local IP)\n\n");
    printf("Press Ctrl+C to stop.\n\n");

    while (!g_stop && tunnel.is_alive()) {
        pollfd pfd{listen_fd, POLLIN, 0};
        if (poll(&pfd, 1, 500) <= 0) continue;

        sockaddr_in peer_addr{};
        socklen_t   peer_len = sizeof(peer_addr);
        int browser_fd = ::accept(listen_fd, (sockaddr*)&peer_addr, &peer_len);
        if (browser_fd < 0) continue;

        // Handle each browser connection in its own thread
        std::thread([&tunnel, browser_fd]() mutable {
            tunnel.handle_browser_connection(browser_fd);
        }).detach();
    }

    ::close(listen_fd);
    printf("\n[proxy-client] Stopped.\n");
    return 0;
}
