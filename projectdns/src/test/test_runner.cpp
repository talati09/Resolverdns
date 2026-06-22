// test_runner.cpp
#include "../headers/dns_resolver.h"
#include "../headers/parser.h"
#include "../headers/cache.h"

#include <fstream>
#include <iostream>
#include <vector>
#include <string>

int main() {
    std::ifstream infile("../test/test_domains.txt");
    if (!infile.is_open()) {
        std::cerr << "❌ Failed to open test_domains.txt\n";
        return 1;
    }

    DNSCache cache("../src/data/cache.json");
    cache.load();

    std::string domain;
    while (std::getline(infile, domain)) {
        if (domain.empty()) continue;

        std::cout << "\n🔍 Resolving: " << domain << std::endl;

        if (cache.contains(domain)) {
            std::cout << "✅ Cached IP: " << cache.get(domain) << std::endl;
            continue;
        }

        DNSResolver resolver(domain);
        if (!resolver.sendQuery()) {
            std::cerr << "❌ Failed to send query for " << domain << std::endl;
            continue;
        }

        std::vector<uint8_t> responseBuffer;
        if (!resolver.receiveResponse(responseBuffer)) {
            std::cerr << "❌ Failed to receive response for " << domain << std::endl;
            continue;
        }

        // PHASE 2 CHANGE: parseResponse now returns ParsedResponse, not vector<string>
        DNSParser parser;
        ParsedResponse result = parser.parseResponse(responseBuffer);

        if (result.hasAnswer()) {
            std::cout << "🌐 Resolved IPs:\n";
            for (const std::string& ip : result.answers) {
                std::cout << "   → " << ip << std::endl;
            }
            cache.insert(domain, result.answers[0]);
        } else if (result.hasNameservers()) {
            std::cout << "📡 Delegated to nameservers:\n";
            for (const auto& ns : result.nameservers) {
                std::cout << "   → " << ns;
                if (result.glue.count(ns)) std::cout << " (glue: " << result.glue[ns] << ")";
                std::cout << std::endl;
            }
        } else {
            std::cerr << "⚠️  No IPs found for " << domain << std::endl;
        }
    }

    return 0;
}