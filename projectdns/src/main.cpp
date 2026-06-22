// main.cpp
#include "headers/dns_resolver.h"
#include "headers/parser.h"
#include "headers/cache.h"
#include <iostream>
#include <string>

int main() {
    std::string hostname;
    std::cout << "Enter the hostname to resolve: ";
    std::cin >> hostname;

    // BUG 5 FIXED: was hardcoded to "e:/projectdns/data/cache.json"
    // That is a Windows absolute path — always fails on Linux/Mac
    // Changed to a relative path that works from the build directory
    DNSCache cache("../src/data/cache.json");
    cache.load();

    // ── Cache check ──
    // If we've resolved this hostname before, return immediately
    if (cache.contains(hostname)) {
        std::cout << "✅ [Cache HIT] IP for " << hostname
                  << ": " << cache.get(hostname) << std::endl;
        return 0;
    }

    std::cout << "🔍 [Cache MISS] Resolving " << hostname << " via DNS..." << std::endl;

    // ── Send DNS query ──
    DNSResolver resolver(hostname);
    if (!resolver.sendQuery()) {
        std::cerr << "❌ Failed to send DNS query." << std::endl;
        return 1;
    }

    // ── Receive response ──
    std::vector<uint8_t> responseBuffer;
    if (!resolver.receiveResponse(responseBuffer)) {
        std::cerr << "❌ Failed to receive DNS response." << std::endl;
        return 1;
    }

    // ── Parse response ──
    // PHASE 2 CHANGE: parseResponse now returns a ParsedResponse struct
    // instead of a flat vector<string>. This holds Answer, Authority (NS),
    // and Additional (glue) sections separately.
    DNSParser parser;
    ParsedResponse result = parser.parseResponse(responseBuffer);

    // ── Output results ──
    if (result.hasAnswer()) {
        // BUG 6 FIXED (Phase 1): previously called cache.insert() inside the loop
        // Each insert() overwrites the previous entry — only the LAST IP survived
        // Fix: print all IPs, but only cache the first one
        std::cout << "🌐 Resolved IPs for " << hostname << ":\n";
        for (const auto& ip : result.answers) {
            std::cout << "   → " << ip << std::endl;
        }
        cache.insert(hostname, result.answers[0]);
        std::cout << "💾 Cached: " << result.answers[0] << std::endl;
    } else if (result.hasNameservers()) {
        // PHASE 2 NEW: when querying 8.8.8.8 you will rarely see this —
        // Google's recursive resolver normally gives a direct answer.
        // But this branch becomes important from Phase 4 onward when we
        // query root/TLD servers directly and they delegate instead of answer.
        std::cout << "📡 No direct answer. Server delegated to these nameservers:\n";
        for (const auto& ns : result.nameservers) {
            std::cout << "   → " << ns;
            if (result.glue.count(ns)) {
                std::cout << "  (glue IP: " << result.glue[ns] << ")";
            }
            std::cout << std::endl;
        }
    } else if (result.hasCname()) {
        std::cout << "🔗 " << hostname << " is an alias (CNAME) for: " << result.cname << std::endl;
        std::cout << "   (Phase 4 will automatically follow this chain)\n";
    } else {
        std::cout << "⚠️  No usable records found in the response.\n";
    }

    return 0;
}