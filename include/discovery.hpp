#pragma once
// ============================================================================
// discovery.hpp — Centralized discovery server + client API
//
// Protocol: line-delimited JSON over TCP (port 7700 by default)
// Request:  {"action":"register"|"lookup"|"heartbeat", ...}
// Response: {"ok":true|false, ...}
//
// Security: register requires a proof-of-ownership signature:
//   sig = Ed25519_sign(node_id_hex || transport_endpoint || timestamp_ms)
// Server verifies sig against the supplied public_key.
// This prevents impersonation at the discovery layer.
// ============================================================================

#include "identity.hpp"
#include "transport.hpp"
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <chrono>
#include <sstream>
#include <atomic>
#include <cstring>

namespace idn {

// ---------------------------------------------------------------------------
// Simple JSON builder (no external deps)
// ---------------------------------------------------------------------------
namespace json {
    inline std::string escape(const std::string& s) {
        std::string r;
        r.reserve(s.size()+2);
        for (char c : s) {
            if      (c == '"')  r += "\\\"";
            else if (c == '\\') r += "\\\\";
            else if (c == '\n') r += "\\n";
            else                r += c;
        }
        return r;
    }

    // Minimal JSON parser — extracts string values from flat objects
    inline std::string get_str(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\":\"";
        auto pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos += search.size();
        auto end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    }

    inline bool get_bool(const std::string& json, const std::string& key) {
        std::string t = "\"" + key + "\":true";
        return json.find(t) != std::string::npos;
    }

    inline uint64_t get_u64(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\":";
        auto pos = json.find(search);
        if (pos == std::string::npos) return 0;
        pos += search.size();
        if (pos < json.size() && json[pos] == '"') ++pos; // skip optional quote
        try { return std::stoull(json.substr(pos)); } catch(...) { return 0; }
    }
}

// ---------------------------------------------------------------------------
// DiscoveryRecord: what we store per registered node
// ---------------------------------------------------------------------------
struct DiscoveryRecord {
    NodeId      node_id{};
    PublicKey   public_key{};
    std::string transport_endpoint;   // "ip:port" — carrier only
    std::vector<std::string> services; // e.g. ["echo","rpc"]
    uint64_t    registered_at_ms = 0;
    uint64_t    last_seen_ms     = 0;
    static constexpr uint64_t TTL_MS = 120'000; // 2 minutes

    bool is_expired(uint64_t now_ms) const {
        return (now_ms - last_seen_ms) > TTL_MS;
    }

    std::string to_json() const {
        std::ostringstream o;
        o << "{\"node_id\":\"" << node_id.to_hex() << "\""
          << ",\"public_key\":\"" << public_key.to_base64() << "\""
          << ",\"endpoint\":\"" << json::escape(transport_endpoint) << "\""
          << ",\"last_seen\":" << last_seen_ms
          << "}";
        return o.str();
    }
};

// ---------------------------------------------------------------------------
// DiscoveryStore: thread-safe in-memory registry
// ---------------------------------------------------------------------------
class DiscoveryStore {
public:
    void upsert(DiscoveryRecord rec) {
        std::lock_guard<std::mutex> lk(mu_);
        rec.last_seen_ms = now_ms();
        if (rec.registered_at_ms == 0)
            rec.registered_at_ms = rec.last_seen_ms;
        store_[rec.node_id] = std::move(rec);
    }

    std::optional<DiscoveryRecord> lookup_by_node_id(const NodeId& id) {
        std::lock_guard<std::mutex> lk(mu_);
        evict_expired_locked();
        auto it = store_.find(id);
        if (it == store_.end()) return std::nullopt;
        return it->second;
    }

    std::optional<DiscoveryRecord> lookup_by_pubkey(const PublicKey& pk) {
        NodeId id = pk.to_node_id();
        return lookup_by_node_id(id);
    }

    bool heartbeat(const NodeId& id) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = store_.find(id);
        if (it == store_.end()) return false;
        it->second.last_seen_ms = now_ms();
        return true;
    }

    size_t count() {
        std::lock_guard<std::mutex> lk(mu_);
        evict_expired_locked();
        return store_.size();
    }

private:
    struct NodeIdHash {
        size_t operator()(const NodeId& id) const {
            size_t h = 0;
            // NodeId.bytes is 32 bytes — iterate 4 blocks of 8 bytes
            for (int i = 0; i < 4; ++i) {
                uint64_t v;
                memcpy(&v, id.bytes.data() + i*8, 8);
                h ^= v + 0x9e3779b9 + (h<<6) + (h>>2);
            }
            return h;
        }
    };

    std::unordered_map<NodeId, DiscoveryRecord, NodeIdHash> store_;
    std::mutex mu_;

    void evict_expired_locked() {
        uint64_t now = now_ms();
        for (auto it = store_.begin(); it != store_.end(); ) {
            if (it->second.is_expired(now)) it = store_.erase(it);
            else ++it;
        }
    }
};

// ---------------------------------------------------------------------------
// DiscoveryServer: TCP server that handles register/lookup/heartbeat requests
// ---------------------------------------------------------------------------
class DiscoveryServer {
public:
    explicit DiscoveryServer(uint16_t port = 7700) : port_(port) {}

    void start() {
        running_ = true;
        thread_  = std::thread([this]{ serve_loop(); });
        printf("[discovery] Server started on 0.0.0.0:%u\n", port_);
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }

    DiscoveryStore& store() { return store_; }

private:
    uint16_t        port_;
    DiscoveryStore  store_;
    std::atomic<bool> running_{false};
    std::thread     thread_;

    void serve_loop() {
        TransportEndpoint ep{"0.0.0.0", port_};
        TcpListener listener = TcpListener::bind(ep);

        while (running_) {
            // Use poll to check for incoming connections with a timeout
            pollfd pfd{listener.fd(), POLLIN, 0};
            if (poll(&pfd, 1, 500) <= 0) continue;

            try {
                auto [stream, peer_ep] = listener.accept();
                // Handle each connection in its own thread
                auto* s = new TcpStream(std::move(stream));
                std::thread([this, s, peer_ep]() mutable {
                    handle_connection(*s, peer_ep);
                    delete s;
                }).detach();
            } catch (const std::exception& e) {
                if (running_)
                    fprintf(stderr, "[discovery] accept error: %s\n", e.what());
            }
        }
    }

    void handle_connection(TcpStream& stream, const TransportEndpoint& peer_ep) {
        // Read a line (JSON request), send JSON response
        char buf[4096];
        int  pos = 0;

        while (pos < (int)sizeof(buf)-1) {
            uint8_t c;
            if (!stream.recv_exact(&c, 1, 5000)) break;
            if (c == '\n') break;
            buf[pos++] = (char)c;
        }
        buf[pos] = '\0';
        if (pos == 0) return;

        std::string req(buf, pos);
        std::string resp = handle_request(req, peer_ep);
        resp += "\n";
        stream.send_all((const uint8_t*)resp.data(), resp.size());
    }

    std::string handle_request(const std::string& req,
                                const TransportEndpoint& peer_ep) {
        std::string action = json::get_str(req, "action");

        if (action == "register") {
            return handle_register(req, peer_ep);
        } else if (action == "lookup") {
            return handle_lookup(req);
        } else if (action == "heartbeat") {
            return handle_heartbeat(req);
        } else if (action == "list") {
            return handle_list();
        }
        return "{\"ok\":false,\"error\":\"unknown action\"}";
    }

    std::string handle_register(const std::string& req,
                                 const TransportEndpoint& peer_ep) {
        std::string pubkey_b64 = json::get_str(req, "public_key");
        std::string endpoint   = json::get_str(req, "endpoint");
        std::string sig_b64    = json::get_str(req, "signature");
        uint64_t    ts         = json::get_u64(req, "timestamp");

        if (pubkey_b64.empty() || sig_b64.empty())
            return "{\"ok\":false,\"error\":\"missing fields\"}";

        // Staleness check ±60s
        uint64_t now = now_ms();
        int64_t drift = (int64_t)now - (int64_t)ts;
        if (drift > 60000 || drift < -60000)
            return "{\"ok\":false,\"error\":\"timestamp stale\"}";

        PublicKey pk;
        try { pk = PublicKey::from_base64(pubkey_b64); }
        catch(...) { return "{\"ok\":false,\"error\":\"bad public_key\"}"; }

        NodeId node_id = pk.to_node_id();

        // Verify proof-of-ownership: sig over node_id_hex || endpoint || timestamp
        std::string transcript = node_id.to_hex() + "|" + endpoint + "|"
                                + std::to_string(ts);
        auto sig_bytes = base64::decode(sig_b64);

        if (sig_bytes.size() != 64)
            return "{\"ok\":false,\"error\":\"bad signature length\"}";

        if (!verify_signature(pk,
                              (const uint8_t*)transcript.data(), transcript.size(),
                              sig_bytes.data(), 64))
            return "{\"ok\":false,\"error\":\"signature verification failed\"}";

        // If endpoint not provided, use peer's transport IP + declared port
        if (endpoint.empty()) endpoint = peer_ep.to_string();

        DiscoveryRecord rec;
        rec.node_id    = node_id;
        rec.public_key = pk;
        rec.transport_endpoint = endpoint;
        store_.upsert(rec);

        printf("[discovery] Registered: %s @ %s\n",
               node_id.fingerprint().c_str(), endpoint.c_str());

        return "{\"ok\":true,\"node_id\":\"" + node_id.to_hex() + "\"}";
    }

    std::string handle_lookup(const std::string& req) {
        std::string node_id_hex = json::get_str(req, "node_id");
        std::string pubkey_b64  = json::get_str(req, "public_key");

        std::optional<DiscoveryRecord> rec;

        if (!node_id_hex.empty()) {
            try {
                NodeId id = NodeId::from_hex(node_id_hex);
                rec = store_.lookup_by_node_id(id);
            } catch(...) {
                return "{\"ok\":false,\"error\":\"bad node_id\"}";
            }
        } else if (!pubkey_b64.empty()) {
            try {
                PublicKey pk = PublicKey::from_base64(pubkey_b64);
                rec = store_.lookup_by_pubkey(pk);
            } catch(...) {
                return "{\"ok\":false,\"error\":\"bad public_key\"}";
            }
        } else {
            return "{\"ok\":false,\"error\":\"provide node_id or public_key\"}";
        }

        if (!rec) return "{\"ok\":false,\"error\":\"not found\"}";
        return "{\"ok\":true,\"record\":" + rec->to_json() + "}";
    }

    std::string handle_heartbeat(const std::string& req) {
        std::string node_id_hex = json::get_str(req, "node_id");
        try {
            NodeId id = NodeId::from_hex(node_id_hex);
            bool ok = store_.heartbeat(id);
            return ok ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"not found\"}";
        } catch(...) {
            return "{\"ok\":false,\"error\":\"bad node_id\"}";
        }
    }

    std::string handle_list() {
        // For debugging only
        return "{\"ok\":true,\"count\":" + std::to_string(store_.count()) + "}";
    }
};

// ---------------------------------------------------------------------------
// DiscoveryClient: used by nodes to register and look up peers
// ---------------------------------------------------------------------------
class DiscoveryClient {
public:
    explicit DiscoveryClient(const TransportEndpoint& server_ep)
        : server_ep_(server_ep) {}

    // Register this node with the discovery server
    // Returns true on success
    bool register_node(const NodeIdentity& id,
                       const TransportEndpoint& my_transport_ep) {
        uint64_t ts = now_ms();
        std::string endpoint = my_transport_ep.to_string();

        // Build proof-of-ownership transcript
        std::string transcript = id.node_id().to_hex() + "|"
                               + endpoint + "|" + std::to_string(ts);

        auto sig = id.sign((const uint8_t*)transcript.data(), transcript.size());
        std::string sig_b64 = base64::encode(sig.data(), 64);

        std::ostringstream req;
        req << "{\"action\":\"register\""
            << ",\"public_key\":\"" << id.public_key().to_base64() << "\""
            << ",\"endpoint\":\"" << json::escape(endpoint) << "\""
            << ",\"timestamp\":" << ts
            << ",\"signature\":\"" << sig_b64 << "\"}";

        auto resp = send_request(req.str());
        bool ok = json::get_bool(resp, "ok");
        if (!ok) {
            fprintf(stderr, "[discovery] register failed: %s\n", resp.c_str());
        }
        return ok;
    }

    // Lookup a node by node_id
    std::optional<DiscoveryRecord> lookup_by_node_id(const NodeId& id) {
        std::ostringstream req;
        req << "{\"action\":\"lookup\",\"node_id\":\"" << id.to_hex() << "\"}";

        auto resp = send_request(req.str());
        if (!json::get_bool(resp, "ok")) return std::nullopt;

        // Parse record from response
        DiscoveryRecord rec;
        std::string node_id_hex = json::get_str(resp, "node_id");
        std::string pubkey_b64  = json::get_str(resp, "public_key");
        std::string endpoint    = json::get_str(resp, "endpoint");

        if (node_id_hex.empty() || pubkey_b64.empty()) return std::nullopt;

        try {
            rec.node_id    = NodeId::from_hex(node_id_hex);
            rec.public_key = PublicKey::from_base64(pubkey_b64);
            rec.transport_endpoint = endpoint;
        } catch(...) { return std::nullopt; }

        return rec;
    }

    // Lookup by public key
    std::optional<DiscoveryRecord> lookup_by_pubkey(const PublicKey& pk) {
        std::ostringstream req;
        req << "{\"action\":\"lookup\",\"public_key\":\""
            << pk.to_base64() << "\"}";

        auto resp = send_request(req.str());
        if (!json::get_bool(resp, "ok")) return std::nullopt;

        DiscoveryRecord rec;
        std::string node_id_hex = json::get_str(resp, "node_id");
        std::string pubkey_b64  = json::get_str(resp, "public_key");
        std::string endpoint    = json::get_str(resp, "endpoint");

        if (node_id_hex.empty() || pubkey_b64.empty()) return std::nullopt;

        try {
            rec.node_id    = NodeId::from_hex(node_id_hex);
            rec.public_key = PublicKey::from_base64(pubkey_b64);
            rec.transport_endpoint = endpoint;
        } catch(...) { return std::nullopt; }

        return rec;
    }

    // Send heartbeat
    bool heartbeat(const NodeId& id) {
        std::ostringstream req;
        req << "{\"action\":\"heartbeat\",\"node_id\":\"" << id.to_hex() << "\"}";
        auto resp = send_request(req.str());
        return json::get_bool(resp, "ok");
    }

private:
    TransportEndpoint server_ep_;

    std::string send_request(const std::string& req) {
        try {
            auto stream = TcpStream::connect(server_ep_, 3000);
            std::string r = req + "\n";
            stream.send_all((const uint8_t*)r.data(), r.size());

            // Read response line
            char buf[8192];
            int pos = 0;
            while (pos < (int)sizeof(buf)-1) {
                uint8_t c;
                if (!stream.recv_exact(&c, 1, 5000)) break;
                if (c == '\n') break;
                buf[pos++] = (char)c;
            }
            buf[pos] = '\0';
            return std::string(buf, pos);
        } catch (const std::exception& e) {
            return std::string("{\"ok\":false,\"error\":\"") + e.what() + "\"}";
        }
    }
};

} // namespace idn
