// ============================================================================
// main_discovery.cpp — Identity Network Discovery Server
//
// Usage: identitynet-discovery [--port PORT]
// ============================================================================

#include "discovery.hpp"
#include <csignal>
#include <cstdlib>
#include <string>

static std::atomic<bool> g_stop{false};

static void sig_handler(int) { g_stop = true; }

int main(int argc, char* argv[]) {
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    uint16_t port = 7700;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--port" || a == "-p") && i+1 < argc)
            port = (uint16_t)std::stoi(argv[++i]);
        else if (a == "--help" || a == "-h") {
            printf("Usage: %s [--port PORT]\n", argv[0]);
            printf("  --port PORT   Listen port (default: 7700)\n");
            return 0;
        }
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║   Identity Network — Discovery Server    ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    printf("[discovery] Starting on port %u\n", port);
    printf("[discovery] Protocol: line-delimited JSON over TCP\n");
    printf("[discovery] Registration requires proof-of-ownership signature\n\n");

    idn::DiscoveryServer server(port);
    server.start();

    // Status loop
    uint64_t last_status = idn::now_ms();
    while (!g_stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        uint64_t now = idn::now_ms();
        if (now - last_status > 30000) {
            printf("[discovery] Active nodes: %zu\n", server.store().count());
            last_status = now;
        }
    }

    printf("\n[discovery] Stopping...\n");
    server.stop();
    printf("[discovery] Stopped. Active nodes at shutdown: %zu\n",
           server.store().count());
    return 0;
}
