// main.cpp
#include "headers/dns_resolver.h"
#include "headers/parser.h"
#include "headers/cache.h"
#include "headers/utils.h"
#include "headers/dns_structs.h"
#include <iostream>
#include <string>
#include <vector>

int main() {
    std::string hostname;
    std::cout << "Enter the hostname to resolve: ";
    std::cin >> hostname;

    // BUG 5 FIXED (Phase 1): was hardcoded Windows path
    DNSCache cache("../src/data/cache.json");
    cache.load();

    // Cache check
    if (cache.contains(hostname)) {
        std::cout << "✅ [Cache HIT] IP for " << hostname
                  << ": " << cache.get(hostname) << std::endl;
        return 0;
    }

    std::cout << "🔍 [Cache MISS] Resolving " << hostname << "...\n";

    // PHASE 3: Load root servers
    std::vector<std::string> rootServers = loadRootServers("../src/data/root_servers.txt");

    if (rootServers.empty()) {
        std::cerr << "⚠️  No root servers found, falling back to 127.0.0.53\n";
        rootServers.push_back("127.0.0.53");
    }

    // PHASE 3: Try each root server until one responds
    std::vector<uint8_t> responseBuffer;
    bool gotResponse = false;
    std::string respondingServer;

    for (const std::string& serverIP : rootServers) {
        DNSResolver resolver(hostname, serverIP);

        if (!resolver.sendQuery()) continue;

        if (resolver.receiveResponse(responseBuffer)) {
            gotResponse = true;
            respondingServer = serverIP;
            break;
        }
        std::cout << "⏭️  No response from " << serverIP << ", trying next...\n";
    }

    if (!gotResponse) {
        std::cerr << "❌ No root server responded. Check your network.\n";
        return 1;
    }

    // PHASE 2: Parse full response
    DNSParser parser;
    ParsedResponse result = parser.parseResponse(responseBuffer);

    // Output results
    if (result.hasAnswer()) {
        std::cout << "🌐 Resolved IPs for " << hostname << ":\n";
        for (const auto& ip : result.answers) {
            std::cout << "   → " << ip << std::endl;
        }
        cache.insert(hostname, result.answers[0]);
        std::cout << "💾 Cached: " << result.answers[0] << std::endl;

    } else if (result.hasNameservers()) {
        std::cout << "📡 Server " << respondingServer << " delegated to:\n";
        for (const auto& ns : result.nameservers) {
            std::cout << "   → " << ns;
            if (result.glue.count(ns)) {
                std::cout << "  (IP: " << result.glue.at(ns) << ")";
            }
            std::cout << std::endl;
        }
        std::cout << "\n💡 Phase 4 will follow this delegation automatically.\n";

    } else if (result.hasCname()) {
        std::cout << "🔗 " << hostname << " is a CNAME alias for: " << result.cname << "\n";

    } else {
        std::cout << "⚠️  No usable records in response.\n";
    }

    return 0;
}