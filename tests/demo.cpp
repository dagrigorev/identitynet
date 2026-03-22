// ============================================================================
// demo.cpp — Full end-to-end demo: discovery + server + client in one process
// Demonstrates all 4 required scenarios from the spec.
// ============================================================================
#include "server.hpp"
#include "client.hpp"
#include <thread>
#include <chrono>
#include <cstdio>
#include <filesystem>

int main() {
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║         Identity Network — Live Demo                 ║\n");
    printf("║  \"Identity IS the address. IP is only a carrier.\"    ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    // ── Discovery ────────────────────────────────────────────────
    printf("▶  Starting discovery server on :17900\n");
    idn::DiscoveryServer disc(17900);
    disc.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // ── Server 1 (open ACL) ──────────────────────────────────────
    printf("▶  Starting identity server on :17901\n");
    std::filesystem::remove("/tmp/demo_srv.key");
    idn::ServerConfig srv_cfg;
    srv_cfg.listen_port        = 17901;
    srv_cfg.identity_key_path  = "/tmp/demo_srv.key";
    srv_cfg.discovery_endpoint = "127.0.0.1:17900";
    srv_cfg.register_on_start  = true;
    srv_cfg.verbose            = false;

    idn::IdentityServer server(srv_cfg);
    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    printf("\n══════════════════════════════════════════════════════\n");
    printf("SERVER IDENTITY (long-term Ed25519 key):\n");
    printf("  NodeId  : %s\n", server.identity().node_id().to_hex().c_str());
    printf("  Finger  : %s\n", server.identity().node_id().fingerprint().c_str());
    printf("  PubKey  : %s\n", server.identity().public_key().to_base64().c_str());
    printf("══════════════════════════════════════════════════════\n\n");

    // ── Client setup ─────────────────────────────────────────────
    std::filesystem::remove("/tmp/demo_cli.key");
    idn::ClientConfig cli_cfg;
    cli_cfg.identity_key_path  = "/tmp/demo_cli.key";
    cli_cfg.discovery_endpoint = "127.0.0.1:17900";
    cli_cfg.verbose            = false;

    idn::IdentityClient client(cli_cfg);
    printf("CLIENT IDENTITY (long-term Ed25519 key):\n");
    printf("  NodeId  : %s\n", client.identity().node_id().to_hex().c_str());
    printf("  Finger  : %s\n", client.identity().node_id().fingerprint().c_str());
    printf("══════════════════════════════════════════════════════\n\n");

    idn::NodeId    srv_node_id = server.identity().node_id();
    idn::PublicKey srv_pubkey  = server.identity().public_key();

    int scenarios_ok = 0, scenarios_total = 0;

    // ══════════════════════════════════════════════════════════════
    // SCENARIO 1 — Connect by node_id via discovery
    // ══════════════════════════════════════════════════════════════
    scenarios_total++;
    printf("┌──────────────────────────────────────────────────────┐\n");
    printf("│ SCENARIO 1: client.connect_by_node_id(node_id)       │\n");
    printf("│  No IP address visible in this call.                 │\n");
    printf("└──────────────────────────────────────────────────────┘\n");
    printf("  Calling: connect_by_node_id(\"%s\")\n",
           srv_node_id.fingerprint().c_str());
    try {
        auto sess = client.connect_by_node_id(srv_node_id);
        printf("  ✓ Handshake complete\n");
        printf("  ✓ Peer identity authenticated: %s\n",
               sess->peer_node_id().fingerprint().c_str());
        printf("  ✓ Ed25519 mutual auth + X25519 ECDH + AES-256-GCM session\n");

        double rtt = idn::IdentityClient::ping(*sess);
        printf("  ✓ PING  rtt=%.3f ms\n", rtt);

        std::string echo = idn::IdentityClient::echo(*sess, "hello identity network");
        printf("  ✓ ECHO  sent=\"hello identity network\"\n");
        printf("  ✓ ECHO  recv=\"%s\"\n", echo.c_str());

        sess->close();
        printf("  ✓ Session closed (sent=%llu recv=%llu bytes)\n",
               (unsigned long long)sess->bytes_sent(),
               (unsigned long long)sess->bytes_recv());
        scenarios_ok++;
    } catch (const std::exception& e) {
        printf("  ✗ FAILED: %s\n", e.what());
    }
    printf("\n");

    // ══════════════════════════════════════════════════════════════
    // SCENARIO 2 — Connect by known public key (pins identity, MITM-resistant)
    // ══════════════════════════════════════════════════════════════
    scenarios_total++;
    printf("┌──────────────────────────────────────────────────────┐\n");
    printf("│ SCENARIO 2: client.connect_by_pubkey(pubkey)         │\n");
    printf("│  Server key is pinned — any impostor is rejected.    │\n");
    printf("└──────────────────────────────────────────────────────┘\n");
    printf("  Calling: connect_by_pubkey(\"%s...\")\n",
           srv_pubkey.to_base64().substr(0,28).c_str());
    try {
        auto sess = client.connect_by_pubkey(srv_pubkey);
        printf("  ✓ Server key matches pinned pubkey — no MITM\n");
        printf("  ✓ Peer: %s\n", sess->peer_node_id().fingerprint().c_str());

        std::string echo = idn::IdentityClient::echo(*sess,
            "pubkey-pinned connection works!");
        printf("  ✓ ECHO  recv=\"%s\"\n", echo.c_str());
        sess->close();
        scenarios_ok++;
    } catch (const std::exception& e) {
        printf("  ✗ FAILED: %s\n", e.what());
    }
    printf("\n");

    // ══════════════════════════════════════════════════════════════
    // SCENARIO 3 — ACL: allow one client, deny another
    // ══════════════════════════════════════════════════════════════
    scenarios_total++;
    printf("┌──────────────────────────────────────────────────────┐\n");
    printf("│ SCENARIO 3: ACL — identity-based access control      │\n");
    printf("│  Server allowlist contains only client1.node_id.     │\n");
    printf("│  client2 (different identity) must be denied.        │\n");
    printf("└──────────────────────────────────────────────────────┘\n");

    // Start server 2 with strict allowlist: only client1
    std::filesystem::remove("/tmp/demo_srv2.key");
    idn::ServerConfig srv2_cfg;
    srv2_cfg.listen_port        = 17902;
    srv2_cfg.identity_key_path  = "/tmp/demo_srv2.key";
    srv2_cfg.discovery_endpoint = "127.0.0.1:17900";
    srv2_cfg.register_on_start  = true;
    srv2_cfg.verbose            = false;
    // Empty ACL file = deny all by default
    { std::ofstream f("/tmp/demo.acl"); f << "# only client1\n"
      << client.identity().node_id().to_hex() << "\n"; }
    srv2_cfg.acl_path = "/tmp/demo.acl";

    idn::IdentityServer server2(srv2_cfg);
    server2.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    printf("  ACL allowlist: [%s]\n\n",
           client.identity().node_id().fingerprint().c_str());

    bool allow_ok = false, deny_ok = false;

    // client1 (in allowlist) — should succeed
    try {
        auto sess = client.connect_by_node_id(server2.identity().node_id());
        double rtt = idn::IdentityClient::ping(*sess);
        sess->close();
        allow_ok = true;
        printf("  ✓ client1 [%s]: ALLOWED (rtt=%.2fms)\n",
               client.identity().node_id().fingerprint().c_str(), rtt);
    } catch (const std::exception& e) {
        printf("  ✗ client1 should be allowed but got: %s\n", e.what());
    }

    // client2 (not in allowlist) — must be rejected
    std::filesystem::remove("/tmp/demo_cli2.key");
    idn::ClientConfig cli2_cfg = cli_cfg;
    cli2_cfg.identity_key_path = "/tmp/demo_cli2.key";
    cli2_cfg.verbose = false;
    idn::IdentityClient client2(cli2_cfg);

    try {
        auto sess = client2.connect_by_node_id(server2.identity().node_id());
        idn::IdentityClient::ping(*sess);
        sess->close();
        printf("  ✗ client2 should be denied but was accepted!\n");
    } catch (...) {
        deny_ok = true;
        printf("  ✓ client2 [%s]: DENIED (not in ACL)\n",
               client2.identity().node_id().fingerprint().c_str());
    }

    if (allow_ok && deny_ok) scenarios_ok++;
    printf("\n");

    // ══════════════════════════════════════════════════════════════
    // SCENARIO 4 — MITM rejected: wrong public key pinned
    // ══════════════════════════════════════════════════════════════
    scenarios_total++;
    printf("┌──────────────────────────────────────────────────────┐\n");
    printf("│ SCENARIO 4: MITM rejected — wrong pubkey pinned      │\n");
    printf("│  Client pins an impostor key → handshake aborts.     │\n");
    printf("└──────────────────────────────────────────────────────┘\n");

    auto impostor = idn::NodeIdentity::generate();
    printf("  Impostor pubkey: %s...\n",
           impostor.public_key().to_base64().substr(0,20).c_str());
    printf("  Real server key: %s...\n",
           srv_pubkey.to_base64().substr(0,20).c_str());
    try {
        // connect_direct bypasses discovery — uses the real server's transport endpoint
        // but pins impostor's pubkey → handshake must reject
        auto sess = client.connect_direct(impostor.public_key(),
                                          {"127.0.0.1", 17901});
        idn::IdentityClient::ping(*sess);
        printf("  ✗ Should have rejected the impostor key!\n");
    } catch (const std::exception& e) {
        printf("  ✓ MITM rejected: %s\n", e.what());
        scenarios_ok++;
    }
    printf("\n");

    // ══════════════════════════════════════════════════════════════
    // STRESS TEST — sequential + concurrent connections
    // ══════════════════════════════════════════════════════════════
    printf("┌──────────────────────────────────────────────────────┐\n");
    printf("│ STRESS TEST: concurrent identity-based connections   │\n");
    printf("└──────────────────────────────────────────────────────┘\n");

    // Sequential
    {
        int n = 100, ok_count = 0;
        double sum_rtt = 0;
        uint64_t t0 = idn::now_monotonic_ms();
        for (int i = 0; i < n; ++i) {
            try {
                auto sess = client.connect_by_node_id(srv_node_id);
                sum_rtt += idn::IdentityClient::ping(*sess);
                sess->close();
                ok_count++;
            } catch (...) {}
        }
        uint64_t ms = idn::now_monotonic_ms() - t0;
        printf("  Sequential  %d/%d  avg_rtt=%.3fms  "
               "throughput=%.0f conn/s  total=%llums\n",
               ok_count, n, sum_rtt / ok_count,
               ok_count * 1000.0 / ms, (unsigned long long)ms);
    }

    // Concurrent
    {
        int n = 200, threads = 8;
        std::atomic<int> ok_count{0};
        std::atomic<double> sum_rtt{0.0};
        uint64_t t0 = idn::now_monotonic_ms();

        std::vector<std::thread> workers;
        for (int t = 0; t < threads; ++t) {
            workers.emplace_back([&]() {
                idn::ClientConfig cfg = cli_cfg;
                cfg.verbose = false;
                idn::IdentityClient c(cfg);
                for (int i = 0; i < n / threads; ++i) {
                    try {
                        auto sess = c.connect_by_node_id(srv_node_id);
                        double rtt = idn::IdentityClient::ping(*sess);
                        sess->close();
                        ok_count++;
                        double old = sum_rtt.load();
                        while (!sum_rtt.compare_exchange_weak(old, old + rtt));
                    } catch (...) {}
                }
            });
        }
        for (auto& w : workers) w.join();

        uint64_t ms = idn::now_monotonic_ms() - t0;
        int done = ok_count.load();
        printf("  Concurrent  %d/%d  %d threads  avg_rtt=%.3fms  "
               "throughput=%.0f conn/s  total=%llums\n",
               done, n, threads,
               done > 0 ? sum_rtt.load() / done : 0.0,
               done * 1000.0 / ms, (unsigned long long)ms);
    }
    printf("\n");

    // ── Cleanup ──────────────────────────────────────────────────
    server.stop();
    server2.stop();
    disc.stop();
    for (auto& p : {"/tmp/demo_srv.key",  "/tmp/demo_srv2.key",
                    "/tmp/demo_cli.key",  "/tmp/demo_cli2.key",
                    "/tmp/demo.acl"})
        std::filesystem::remove(p);

    // ── Summary ──────────────────────────────────────────────────
    printf("══════════════════════════════════════════════════════\n");
    printf("DEMO RESULTS: %d/%d scenarios passed\n",
           scenarios_ok, scenarios_total);
    if (scenarios_ok == scenarios_total)
        printf("ALL SCENARIOS PASSED ✓\n");
    else
        printf("SOME SCENARIOS FAILED\n");
    printf("══════════════════════════════════════════════════════\n");

    return scenarios_ok == scenarios_total ? 0 : 1;
}
