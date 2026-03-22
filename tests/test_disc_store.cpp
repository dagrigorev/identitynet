#include "identity.hpp"
#include "transport.hpp"
#include "discovery.hpp"
#include <cstdio>

int main() {
    idn::DiscoveryStore store;
    auto id = idn::NodeIdentity::generate();
    
    idn::DiscoveryRecord rec;
    rec.node_id = id.node_id();
    rec.public_key = id.public_key();
    rec.transport_endpoint = "127.0.0.1:9999";
    
    store.upsert(rec);
    printf("count after upsert: %zu\n", store.count());
    
    auto found = store.lookup_by_node_id(id.node_id());
    printf("lookup: %s\n", found.has_value() ? "FOUND" : "NOT FOUND");
    if (found) {
        printf("  last_seen_ms = %llu\n", (unsigned long long)found->last_seen_ms);
        printf("  now_ms       = %llu\n", (unsigned long long)idn::now_ms());
        uint64_t diff = idn::now_ms() - found->last_seen_ms;
        printf("  diff = %llu ms  (TTL=%llu)\n", 
               (unsigned long long)diff,
               (unsigned long long)idn::DiscoveryRecord::TTL_MS);
        printf("  expired? %s\n", found->is_expired(idn::now_ms()) ? "YES" : "NO");
    }
    return 0;
}
