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
    DNSParser parser;
    std::vector<std::string> ipAddresses = parser.parseResponse(responseBuffer);

    // ── Output results ──
    if (ipAddresses.empty()) {
        std::cout << "⚠️  No A record IPs found in the response.\n";
    } else {
        // BUG 6 FIXED: previously called cache.insert() inside the loop
        // Each insert() overwrites the previous entry — only the LAST IP survived
        // Fix: print all IPs, but only cache the first one
        std::cout << "🌐 Resolved IPs for " << hostname << ":\n";
        for (const auto& ip : ipAddresses) {
            std::cout << "   → " << ip << std::endl;
        }
        cache.insert(hostname, ipAddresses[0]);
        std::cout << "💾 Cached: " << ipAddresses[0] << std::endl;
    }

    return 0;
}