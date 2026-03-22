#pragma once
// ============================================================================
// authz.hpp — Authorization policy: identity-based ACL
//
// Authorization is always by NodeId (cryptographic identity), never by IP.
// Supports:
//   - allowlist of permitted node_ids
//   - wildcard "allow all" mode (for open servers/demos)
//   - deny list for explicit block
// ============================================================================

#include "identity.hpp"
#include <unordered_set>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <mutex>

namespace idn {

enum class AuthzDecision { ALLOW, DENY };

class AuthorizationPolicy {
public:
    // Create an open policy (allow all authenticated peers)
    static AuthorizationPolicy allow_all() {
        AuthorizationPolicy p;
        p.allow_all_ = true;
        return p;
    }

    // Create a strict allowlist policy
    static AuthorizationPolicy allowlist(std::vector<NodeId> allowed_ids) {
        AuthorizationPolicy p;
        p.allow_all_ = false;
        for (auto& id : allowed_ids)
            p.allowed_.insert(id.to_hex());
        return p;
    }

    // Load from a text file — one node_id hex per line, # comments
    static AuthorizationPolicy load_from_file(const std::string& path) {
        AuthorizationPolicy p;
        p.allow_all_ = false;

        std::ifstream f(path);
        if (!f) {
            fprintf(stderr, "[authz] Warning: ACL file not found: %s — denying all\n",
                    path.c_str());
            return p;
        }

        std::string line;
        while (std::getline(f, line)) {
            // Strip comments and whitespace
            auto pos = line.find('#');
            if (pos != std::string::npos) line = line.substr(0, pos);
            while (!line.empty() && isspace(line.back())) line.pop_back();
            while (!line.empty() && isspace(line.front())) line = line.substr(1);

            if (line == "*") {
                p.allow_all_ = true;
                return p;
            }
            if (line.size() == 64) {
                // Validate it's hex
                bool valid = true;
                for (char c : line) {
                    if (!isxdigit(c)) { valid = false; break; }
                }
                if (valid) p.allowed_.insert(line);
            }
        }
        return p;
    }

    // Add a single node_id to the allowlist
    void permit(const NodeId& id) {
        std::lock_guard<std::mutex> lk(mu_);
        allowed_.insert(id.to_hex());
    }

    // Block a node_id explicitly
    void deny(const NodeId& id) {
        std::lock_guard<std::mutex> lk(mu_);
        denied_.insert(id.to_hex());
    }

    // Check if a peer is authorized
    AuthzDecision check(const NodeId& peer_id) const {
        std::lock_guard<std::mutex> lk(mu_);
        std::string hex = peer_id.to_hex();

        // Explicit deny always wins
        if (denied_.count(hex)) return AuthzDecision::DENY;

        if (allow_all_) return AuthzDecision::ALLOW;

        return allowed_.count(hex) ? AuthzDecision::ALLOW : AuthzDecision::DENY;
    }

    bool is_allowed(const NodeId& id) const {
        return check(id) == AuthzDecision::ALLOW;
    }

    // Save allowlist to file
    void save_to_file(const std::string& path) const {
        std::lock_guard<std::mutex> lk(mu_);
        std::ofstream f(path);
        if (!f) throw std::runtime_error("Cannot write ACL file: " + path);
        f << "# Identity Network ACL\n";
        f << "# One node_id (64-char hex) per line. Use * for allow-all.\n\n";
        if (allow_all_) { f << "*\n"; return; }
        for (const auto& id : allowed_) f << id << "\n";
    }

    size_t allowed_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return allowed_.size();
    }

    bool is_open() const { return allow_all_; }

public:
    AuthorizationPolicy() = default;

    // Move constructor: mutex is not movable, just default-construct a new one
    AuthorizationPolicy(AuthorizationPolicy&& o) noexcept
        : allow_all_(o.allow_all_),
          allowed_(std::move(o.allowed_)),
          denied_(std::move(o.denied_)) {}

    AuthorizationPolicy& operator=(AuthorizationPolicy&& o) noexcept {
        if (this != &o) {
            allow_all_ = o.allow_all_;
            allowed_   = std::move(o.allowed_);
            denied_    = std::move(o.denied_);
        }
        return *this;
    }

    AuthorizationPolicy(const AuthorizationPolicy&) = delete;
    AuthorizationPolicy& operator=(const AuthorizationPolicy&) = delete;

private:
    bool allow_all_ = false;
    mutable std::mutex mu_;
    std::unordered_set<std::string> allowed_;
    std::unordered_set<std::string> denied_;
};

} // namespace idn
