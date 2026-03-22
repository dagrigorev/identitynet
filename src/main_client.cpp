// ============================================================================
// main_client.cpp — Identity Network Client CLI
//
// Commands:
//   identitynet-client init
//   identitynet-client show
//   identitynet-client connect  --node NODE_ID | --pubkey PUBKEY
//   identitynet-client ping     --node NODE_ID | --pubkey PUBKEY  [--count N]
//   identitynet-client echo     --node NODE_ID | --pubkey PUBKEY  --message MSG
//   identitynet-client resolve  --node NODE_ID | --pubkey PUBKEY
// ============================================================================

#include "client.hpp"
#include <cstring>
#include <filesystem>

static void cmd_init(int argc, char* argv[]) {
    std::string key_path = "client.key";
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--key" || a == "-k") && i+1 < argc) key_path = argv[++i];
    }

    if (std::filesystem::exists(key_path)) {
        printf("[client] Key file already exists: %s\n", key_path.c_str());
        auto id = idn::KeyStore::load(key_path);
        idn::KeyStore::print_identity(id);
        return;
    }

    auto id = idn::NodeIdentity::generate();
    idn::KeyStore::save(id, key_path);
    idn::KeyStore::save_public(id, key_path + ".pub");
    printf("[client] Generated new identity.\n");
    printf("[client] Private key: %s\n", key_path.c_str());
    printf("[client] Public key:  %s.pub\n\n", key_path.c_str());
    idn::KeyStore::print_identity(id);
}

static void cmd_show(int argc, char* argv[]) {
    std::string key_path = "client.key";
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--key" || a == "-k") && i+1 < argc) key_path = argv[++i];
    }
    if (!std::filesystem::exists(key_path)) {
        fprintf(stderr, "Key file not found: %s (run 'init' first)\n", key_path.c_str());
        return;
    }
    auto id = idn::KeyStore::load(key_path);
    idn::KeyStore::print_identity(id);
}

// Parse common target options (--node or --pubkey)
struct Target {
    bool        by_node_id = false;
    bool        by_pubkey  = false;
    idn::NodeId node_id{};
    idn::PublicKey pubkey{};
};

static bool parse_target(int argc, char* argv[], int start, Target& tgt) {
    for (int i = start; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--node" || a == "-n") && i+1 < argc) {
            tgt.node_id    = idn::NodeId::from_hex(argv[++i]);
            tgt.by_node_id = true;
        } else if ((a == "--pubkey" || a == "-pk") && i+1 < argc) {
            tgt.pubkey    = idn::PublicKey::from_base64(argv[++i]);
            tgt.by_pubkey = true;
        }
    }
    return tgt.by_node_id || tgt.by_pubkey;
}

static std::unique_ptr<idn::SecureSession>
connect_to_target(idn::IdentityClient& client, const Target& tgt) {
    if (tgt.by_node_id) return client.connect_by_node_id(tgt.node_id);
    if (tgt.by_pubkey)  return client.connect_by_pubkey(tgt.pubkey);
    throw std::runtime_error("No target specified");
}

static idn::ClientConfig parse_client_cfg(int argc, char* argv[]) {
    idn::ClientConfig cfg;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--key"  || a == "-k") && i+1 < argc) cfg.identity_key_path  = argv[++i];
        if ((a == "--discovery" || a == "-d") && i+1 < argc) cfg.discovery_endpoint = argv[++i];
        if (a == "--quiet") cfg.verbose = false;
    }
    return cfg;
}

static void cmd_ping(int argc, char* argv[]) {
    auto cfg = parse_client_cfg(argc, argv);
    Target tgt;
    int count = 4;
    std::string discovery;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--count" || a == "-c") && i+1 < argc) count = std::stoi(argv[++i]);
    }

    if (!parse_target(argc, argv, 2, tgt)) {
        fprintf(stderr, "Error: --node NODE_ID or --pubkey PUBKEY required\n");
        return;
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║    Identity Network — PING               ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    try {
        idn::IdentityClient client(cfg);
        auto sess = connect_to_target(client, tgt);

        printf("\nPINGING identity %s\n\n",
               sess->peer_node_id().fingerprint().c_str());

        double sum = 0, min_rtt = 1e9, max_rtt = 0;
        int ok = 0;

        for (int i = 0; i < count; ++i) {
            try {
                double rtt = idn::IdentityClient::ping(*sess);
                printf("  ping seq=%d  rtt=%.2f ms  peer=%s\n",
                       i+1, rtt, sess->peer_node_id().fingerprint().c_str());
                sum += rtt;
                min_rtt = std::min(min_rtt, rtt);
                max_rtt = std::max(max_rtt, rtt);
                ok++;
            } catch (const std::exception& e) {
                printf("  ping seq=%d  FAILED: %s\n", i+1, e.what());
            }
            if (i < count-1)
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        printf("\n--- %s ping statistics ---\n",
               sess->peer_node_id().fingerprint().c_str());
        printf("%d packets transmitted, %d received\n", count, ok);
        if (ok > 0)
            printf("rtt min/avg/max = %.2f/%.2f/%.2f ms\n",
                   min_rtt, sum/ok, max_rtt);

        sess->close();
    } catch (const std::exception& e) {
        fprintf(stderr, "\n[error] %s\n", e.what());
    }
}

static void cmd_echo(int argc, char* argv[]) {
    auto cfg = parse_client_cfg(argc, argv);
    Target tgt;
    std::string message = "Hello, Identity Network!";

    parse_target(argc, argv, 2, tgt);
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--message" || a == "-m") && i+1 < argc) message = argv[++i];
    }

    if (!tgt.by_node_id && !tgt.by_pubkey) {
        fprintf(stderr, "Error: --node NODE_ID or --pubkey PUBKEY required\n");
        return;
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║    Identity Network — ECHO               ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    try {
        idn::IdentityClient client(cfg);
        auto sess = connect_to_target(client, tgt);

        printf("Connected to: %s\n", sess->peer_node_id().fingerprint().c_str());
        printf("Sending:  \"%s\"\n", message.c_str());

        std::string resp = idn::IdentityClient::echo(*sess, message);

        printf("Received: \"%s\"\n", resp.c_str());
        printf("\nSession stats: sent=%llu recv=%llu bytes\n",
               (unsigned long long)sess->bytes_sent(),
               (unsigned long long)sess->bytes_recv());

        sess->close();
    } catch (const std::exception& e) {
        fprintf(stderr, "\n[error] %s\n", e.what());
    }
}

static void cmd_resolve(int argc, char* argv[]) {
    auto cfg = parse_client_cfg(argc, argv);
    Target tgt;
    parse_target(argc, argv, 2, tgt);

    if (!tgt.by_node_id && !tgt.by_pubkey) {
        fprintf(stderr, "Error: --node NODE_ID or --pubkey PUBKEY required\n");
        return;
    }

    try {
        auto disc_ep = idn::TransportEndpoint::from_string(cfg.discovery_endpoint);
        idn::DiscoveryClient disc(disc_ep);

        std::optional<idn::DiscoveryRecord> rec;
        if (tgt.by_node_id) rec = disc.lookup_by_node_id(tgt.node_id);
        else                 rec = disc.lookup_by_pubkey(tgt.pubkey);

        if (!rec) {
            printf("Node not found in discovery.\n");
            return;
        }

        printf("Discovery record:\n");
        printf("  Node ID:   %s\n", rec->node_id.to_hex().c_str());
        printf("  Fingerprint: %s\n", rec->node_id.fingerprint().c_str());
        printf("  Public Key: %s\n", rec->public_key.to_base64().c_str());
        printf("  Endpoint:  %s (carrier transport — not identity)\n",
               rec->transport_endpoint.c_str());
    } catch (const std::exception& e) {
        fprintf(stderr, "[error] %s\n", e.what());
    }
}

static void cmd_stress(int argc, char* argv[]) {
    auto cfg = parse_client_cfg(argc, argv);
    cfg.verbose = false;
    Target tgt;
    parse_target(argc, argv, 2, tgt);
    int count = 1000;
    int threads = 4;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--count" || a == "-c") && i+1 < argc)   count   = std::stoi(argv[++i]);
        if ((a == "--threads" || a == "-t") && i+1 < argc) threads = std::stoi(argv[++i]);
    }

    if (!tgt.by_node_id && !tgt.by_pubkey) {
        fprintf(stderr, "Error: --node NODE_ID or --pubkey PUBKEY required\n");
        return;
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║    Identity Network — STRESS TEST        ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    printf("Requests: %d  Threads: %d\n\n", count, threads);

    std::atomic<int>    completed{0}, errors{0};
    std::atomic<double> total_rtt{0.0};
    uint64_t t_start = idn::now_monotonic_ms();

    std::vector<std::thread> worker_threads;
    int per_thread = count / threads;

    for (int t = 0; t < threads; ++t) {
        worker_threads.emplace_back([&, t]() {
            for (int i = 0; i < per_thread; ++i) {
                try {
                    idn::IdentityClient client(cfg);
                    auto sess = connect_to_target(client, tgt);
                    double rtt = idn::IdentityClient::ping(*sess);
                    sess->close();
                    completed++;
                    // Atomic double add (approximate)
                    double old = total_rtt.load();
                    while (!total_rtt.compare_exchange_weak(old, old + rtt)) {}
                } catch (...) {
                    errors++;
                }
            }
        });
    }

    for (auto& th : worker_threads) th.join();

    uint64_t elapsed = idn::now_monotonic_ms() - t_start;
    int done = completed.load();

    printf("Results:\n");
    printf("  Completed:  %d / %d\n", done, count);
    printf("  Errors:     %d\n", errors.load());
    printf("  Duration:   %llu ms\n", (unsigned long long)elapsed);
    if (done > 0) {
        printf("  Avg RTT:    %.2f ms\n", total_rtt.load() / done);
        printf("  Throughput: %.1f req/s\n", done * 1000.0 / elapsed);
    }
}

static void print_usage(const char* prog) {
    printf("Identity Network Client\n\n");
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  init                 Generate client identity\n");
    printf("  show                 Show current identity\n");
    printf("  ping   --node ID     Ping a server by node_id\n");
    printf("  echo   --node ID --message MSG\n");
    printf("  resolve --node ID    Resolve node in discovery\n");
    printf("  stress --node ID     High-load stress test\n\n");
    printf("Target options:\n");
    printf("  --node NODEID        Target by 64-hex node_id\n");
    printf("  --pubkey B64KEY      Target by base64 public key\n\n");
    printf("Connection options:\n");
    printf("  --key PATH           Identity key file (default: client.key)\n");
    printf("  --discovery HOST:PORT  Discovery server (default: 127.0.0.1:7700)\n");
    printf("  --quiet              Less verbose\n\n");
    printf("Note: IP addresses are never used as identifiers.\n");
    printf("      Identity IS the address.\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    try {
        if      (cmd == "init")    cmd_init(argc, argv);
        else if (cmd == "show")    cmd_show(argc, argv);
        else if (cmd == "ping")    cmd_ping(argc, argv);
        else if (cmd == "echo")    cmd_echo(argc, argv);
        else if (cmd == "resolve") cmd_resolve(argc, argv);
        else if (cmd == "stress")  cmd_stress(argc, argv);
        else if (cmd == "--help" || cmd == "-h") print_usage(argv[0]);
        else {
            fprintf(stderr, "Unknown command: %s\n\n", cmd.c_str());
            print_usage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        fprintf(stderr, "[fatal] %s\n", e.what());
        return 1;
    }
    return 0;
}
