// ============================================================================
// main_server.cpp — Identity Network Server Node CLI
//
// Commands:
//   identitynet-server init   [--key PATH]
//   identitynet-server run    [--key PATH] [--port PORT] [--acl PATH]
//                             [--discovery HOST:PORT] [--allow-all]
//                             [--no-register]
// ============================================================================

#include "server.hpp"
#include <csignal>
#include <cstring>
#include <filesystem>

static idn::IdentityServer* g_server = nullptr;
static std::atomic<bool>    g_stop{false};

static void sig_handler(int) {
    g_stop = true;
    if (g_server) g_server->stop();
}

static void cmd_init(int argc, char* argv[]) {
    std::string key_path = "server.key";

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--key" || a == "-k") && i+1 < argc)
            key_path = argv[++i];
    }

    if (std::filesystem::exists(key_path)) {
        printf("[server] Key file already exists: %s\n", key_path.c_str());
        printf("[server] Loading existing identity...\n");
        auto id = idn::KeyStore::load(key_path);
        idn::KeyStore::print_identity(id);
        return;
    }

    printf("[server] Generating new identity...\n");
    auto id = idn::NodeIdentity::generate();
    idn::KeyStore::save(id, key_path);
    idn::KeyStore::save_public(id, key_path + ".pub");
    printf("[server] Saved to: %s\n", key_path.c_str());
    printf("[server] Public key saved to: %s.pub\n\n", key_path.c_str());
    idn::KeyStore::print_identity(id);
}

static void cmd_run(int argc, char* argv[]) {
    idn::ServerConfig cfg;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--key"  || a == "-k") && i+1 < argc) cfg.identity_key_path  = argv[++i];
        else if ((a == "--port" || a == "-p") && i+1 < argc) cfg.listen_port    = (uint16_t)std::stoi(argv[++i]);
        else if ((a == "--host" || a == "-H") && i+1 < argc) cfg.listen_host    = argv[++i];
        else if ((a == "--acl") && i+1 < argc)  cfg.acl_path                    = argv[++i];
        else if ((a == "--discovery" || a == "-d") && i+1 < argc) cfg.discovery_endpoint = argv[++i];
        else if (a == "--allow-all")    cfg.acl_path                            = "";
        else if (a == "--no-register")  cfg.register_on_start                   = false;
        else if (a == "--quiet")        cfg.verbose                              = false;
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║    Identity Network — Server Node        ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    idn::IdentityServer server(cfg);
    g_server = &server;
    server.start();

    printf("\n[server] Ready. Press Ctrl+C to stop.\n\n");

    while (!g_stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    printf("\n[server] Stopping...\n");
}

static void print_usage(const char* prog) {
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  init     Generate a new server identity\n");
    printf("  run      Start the server\n\n");
    printf("Options for 'run':\n");
    printf("  --key PATH        Identity key file (default: server.key)\n");
    printf("  --port PORT       Listen port (default: 7701)\n");
    printf("  --host HOST       Listen host (default: 0.0.0.0)\n");
    printf("  --acl PATH        ACL file (one node_id hex per line)\n");
    printf("  --discovery EP    Discovery server endpoint (default: 127.0.0.1:7700)\n");
    printf("  --allow-all       Accept all authenticated peers (no ACL)\n");
    printf("  --no-register     Don't register with discovery on start\n");
    printf("  --quiet           Less verbose output\n\n");
    printf("Example ACL file (acl.txt):\n");
    printf("  # Allow specific peer\n");
    printf("  a1b2c3d4e5f6...   (64-char hex node_id)\n");
    printf("  # Allow all: use * on a single line\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "init")           cmd_init(argc, argv);
    else if (cmd == "run")       cmd_run(argc, argv);
    else if (cmd == "--help" || cmd == "-h") print_usage(argv[0]);
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd.c_str());
        print_usage(argv[0]);
        return 1;
    }
    return 0;
}
