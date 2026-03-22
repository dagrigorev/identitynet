#pragma once
// ============================================================================
// keystore.hpp — Persist and load node identity keys
//
// Format: simple text file with base64-encoded fields
//   version: 1
//   private_key: <base64 of 32-byte seed>
//   public_key:  <base64 of 32-byte public key>
//   node_id:     <hex of 32-byte SHA-256(public_key)>
//   created_at:  <unix timestamp ms>
// ============================================================================

#include "identity.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <sys/stat.h>

namespace idn {

class KeyStore {
public:
    // Save identity to file (private key only: seed + metadata)
    static void save(const NodeIdentity& id, const std::string& path) {
        std::ofstream f(path, std::ios::out | std::ios::trunc);
        if (!f) throw std::runtime_error("Cannot write key file: " + path);

        f << "version: 1\n";
        f << "private_key: "
          << base64::encode(id.private_seed().data(), 32) << "\n";
        f << "public_key: "
          << id.public_key().to_base64() << "\n";
        f << "node_id: "
          << id.node_id().to_hex() << "\n";
        f << "created_at: "
          << std::to_string(now_ms_static()) << "\n";
        f.close();

        // Restrict to owner-only read (private key material)
        chmod(path.c_str(), 0600);
    }

    // Load identity from file
    static NodeIdentity load(const std::string& path) {
        std::ifstream f(path);
        if (!f) throw std::runtime_error("Cannot read key file: " + path);

        std::string line, priv_b64;
        while (std::getline(f, line)) {
            if (line.rfind("private_key: ", 0) == 0)
                priv_b64 = line.substr(13);
        }
        if (priv_b64.empty())
            throw std::runtime_error("No private_key found in: " + path);

        auto seed = base64::decode(priv_b64);
        return NodeIdentity::from_private_bytes(seed);
    }

    // Load or generate (creates new identity if file doesn't exist)
    static NodeIdentity load_or_generate(const std::string& path) {
        if (std::filesystem::exists(path)) {
            return load(path);
        }
        auto id = NodeIdentity::generate();
        // Create parent directories if needed
        auto parent = std::filesystem::path(path).parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent);
        save(id, path);
        return id;
    }

    // Save just the public key to a separate file (for sharing)
    static void save_public(const NodeIdentity& id, const std::string& path) {
        std::ofstream f(path);
        if (!f) throw std::runtime_error("Cannot write pubkey file: " + path);
        f << "version: 1\n";
        f << "public_key: " << id.public_key().to_base64() << "\n";
        f << "node_id: "    << id.node_id().to_hex() << "\n";
    }

    // Load a public key from file (for adding to allowlist, known peers, etc.)
    static PublicKey load_public_key(const std::string& path) {
        std::ifstream f(path);
        if (!f) throw std::runtime_error("Cannot read pubkey file: " + path);
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("public_key: ", 0) == 0)
                return PublicKey::from_base64(line.substr(12));
        }
        throw std::runtime_error("No public_key in: " + path);
    }

    // Print identity info to stdout
    static void print_identity(const NodeIdentity& id) {
        printf("Identity:\n");
        printf("  Node ID:     %s\n", id.node_id().to_hex().c_str());
        printf("  Fingerprint: %s\n", id.node_id().fingerprint().c_str());
        printf("  Public Key:  %s\n", id.public_key().to_base64().c_str());
    }

private:
    static uint64_t now_ms_static() {
        using namespace std::chrono;
        return (uint64_t)duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()).count();
    }
};

} // namespace idn
