#pragma once
// ============================================================================
// transport.hpp — TCP transport layer (IP is carrier, not identity)
// Provides framed message send/recv over a TCP socket.
// IP:port is ephemeral metadata; identity is the authoritative address.
// ============================================================================

#include "protocol.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <optional>
#include <atomic>
#include <mutex>
#include <chrono>

namespace idn {

// ---------------------------------------------------------------------------
// TransportEndpoint: IP:port (purely a "carrier address", not identity)
// ---------------------------------------------------------------------------
struct TransportEndpoint {
    std::string host;
    uint16_t    port = 0;

    std::string to_string() const { return host + ":" + std::to_string(port); }

    static TransportEndpoint from_string(const std::string& s) {
        auto pos = s.rfind(':');
        if (pos == std::string::npos) throw std::invalid_argument("bad endpoint: " + s);
        return { s.substr(0, pos), (uint16_t)std::stoi(s.substr(pos+1)) };
    }
};

// ---------------------------------------------------------------------------
// TcpStream: raw socket wrapper with RAII
// ---------------------------------------------------------------------------
class TcpStream {
public:
    explicit TcpStream(int fd) : fd_(fd) {}

    TcpStream(const TcpStream&) = delete;
    TcpStream& operator=(const TcpStream&) = delete;

    TcpStream(TcpStream&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }

    ~TcpStream() { if (fd_ >= 0) { ::shutdown(fd_, SHUT_RDWR); ::close(fd_); } }

    int fd() const { return fd_; }
    bool valid() const { return fd_ >= 0; }

    // Connect to endpoint
    static TcpStream connect(const TransportEndpoint& ep, int timeout_ms = 5000) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) throw std::runtime_error("socket() failed: " + std::string(strerror(errno)));

        // Set non-blocking for connect with timeout
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(ep.port);
        if (inet_pton(AF_INET, ep.host.c_str(), &addr.sin_addr) <= 0) {
            ::close(fd);
            throw std::runtime_error("Invalid address: " + ep.host);
        }

        int r = ::connect(fd, (sockaddr*)&addr, sizeof(addr));
        if (r < 0 && errno != EINPROGRESS) {
            ::close(fd);
            throw std::runtime_error("connect() failed: " + std::string(strerror(errno)));
        }

        if (r != 0) {
            // Wait for connection
            pollfd pfd{fd, POLLOUT, 0};
            int pr = poll(&pfd, 1, timeout_ms);
            if (pr <= 0) {
                ::close(fd);
                throw std::runtime_error(pr == 0 ? "connect timeout" : "poll error");
            }
            int err = 0;
            socklen_t elen = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
            if (err != 0) {
                ::close(fd);
                throw std::runtime_error("connect failed: " + std::string(strerror(err)));
            }
        }

        // Restore blocking
        fcntl(fd, F_SETFL, flags);

        // Enable TCP_NODELAY for lower latency
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        return TcpStream(fd);
    }

    // Send all bytes (blocking)
    bool send_all(const uint8_t* data, size_t len) {
        std::lock_guard<std::mutex> lk(send_mu_);
        size_t sent = 0;
        while (sent < len) {
            ssize_t r = ::send(fd_, data + sent, len - sent, MSG_NOSIGNAL);
            if (r <= 0) return false;
            sent += r;
        }
        return true;
    }

    bool send_all(const std::vector<uint8_t>& v) {
        return send_all(v.data(), v.size());
    }

    // Receive exactly `len` bytes (blocking)
    bool recv_exact(uint8_t* buf, size_t len, int timeout_ms = 30000) {
        size_t got = 0;
        while (got < len) {
            if (timeout_ms > 0) {
                pollfd pfd{fd_, POLLIN, 0};
                int r = poll(&pfd, 1, timeout_ms);
                if (r <= 0) return false;
            }
            ssize_t r = ::recv(fd_, buf + got, len - got, 0);
            if (r <= 0) return false;
            got += r;
        }
        return true;
    }

    // Read a framed message: header + payload
    std::optional<std::pair<proto::WireHeader, std::vector<uint8_t>>>
    read_frame(int timeout_ms = 30000) {
        uint8_t hdr_buf[sizeof(proto::WireHeader)];
        if (!recv_exact(hdr_buf, sizeof(hdr_buf), timeout_ms)) return std::nullopt;

        proto::WireHeader hdr;
        uint32_t magic = proto::read_u32_be(hdr_buf);
        if (magic != proto::MAGIC) return std::nullopt;
        hdr.magic       = magic;
        hdr.version     = hdr_buf[4];
        hdr.msg_type    = hdr_buf[5];
        hdr.flags       = proto::read_u16_be(hdr_buf+6);
        hdr.payload_len = proto::read_u32_be(hdr_buf+8);

        if (hdr.payload_len > 16*1024*1024)  // 16 MB sanity limit
            return std::nullopt;

        std::vector<uint8_t> payload(hdr.payload_len);
        if (hdr.payload_len > 0) {
            if (!recv_exact(payload.data(), hdr.payload_len, timeout_ms))
                return std::nullopt;
        }
        return std::make_pair(hdr, std::move(payload));
    }

    // Send a framed message
    bool send_frame(proto::MsgType type, const std::vector<uint8_t>& payload,
                    uint16_t flags = 0) {
        auto msg = proto::frame(type, payload, flags);
        return send_all(msg);
    }

    bool send_frame(proto::MsgType type, uint16_t flags = 0) {
        return send_frame(type, {}, flags);
    }

private:
    int fd_;
    std::mutex send_mu_;
};

// ---------------------------------------------------------------------------
// TcpListener: accept incoming connections
// ---------------------------------------------------------------------------
class TcpListener {
public:
    static TcpListener bind(const TransportEndpoint& ep, int backlog = 128) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) throw std::runtime_error("socket() failed");

        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(ep.port);
        if (ep.host == "0.0.0.0" || ep.host.empty())
            addr.sin_addr.s_addr = INADDR_ANY;
        else
            inet_pton(AF_INET, ep.host.c_str(), &addr.sin_addr);

        if (::bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
            ::close(fd);
            throw std::runtime_error("bind() failed: " + std::string(strerror(errno)));
        }
        if (::listen(fd, backlog) < 0) {
            ::close(fd);
            throw std::runtime_error("listen() failed");
        }
        return TcpListener(fd);
    }

    ~TcpListener() { if (fd_ >= 0) ::close(fd_); }
    TcpListener(const TcpListener&) = delete;
    TcpListener(TcpListener&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }

    // Accept one connection, returns (stream, remote_endpoint)
    // remote endpoint is TRANSPORT metadata only — not identity!
    std::pair<TcpStream, TransportEndpoint> accept() {
        sockaddr_in addr{};
        socklen_t alen = sizeof(addr);
        int cfd = ::accept(fd_, (sockaddr*)&addr, &alen);
        if (cfd < 0) throw std::runtime_error("accept() failed: " + std::string(strerror(errno)));

        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
        TransportEndpoint ep{ std::string(buf), ntohs(addr.sin_port) };

        int one = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        return { TcpStream(cfd), ep };
    }

    int fd() const { return fd_; }

private:
    explicit TcpListener(int fd) : fd_(fd) {}
    int fd_;
};

// ---------------------------------------------------------------------------
// Simple timer utility
// ---------------------------------------------------------------------------
inline uint64_t now_ms() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
}

inline uint64_t now_monotonic_ms() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(
        steady_clock::now().time_since_epoch()).count();
}

} // namespace idn
