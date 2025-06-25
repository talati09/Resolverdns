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

    DNSCache cache("src/data/cache.json"); // Adjust path as per project layout
    cache.load(); // Load existing cache

    std::string domain;
    while (std::getline(infile, domain)) {
        if (domain.empty()) continue;

        std::cout << "\n🔍 Resolving: " << domain << std::endl;

        // Check cache first
        if (cache.isCached(domain)) {
            std::cout << "✅ Cached IP: " << cache.getIP(domain) << std::endl;
            continue;
        }

        // Perform DNS resolution
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

        // Parse the response
        std::vector<std::string> ipAddresses = DNSParser::parseResponse(responseBuffer);
        if (!ipAddresses.empty()) {
            std::cout << "🌐 Resolved IPs:\n";
            for (const std::string& ip : ipAddresses) {
                std::cout << " - " << ip << std::endl;
            }

            // Cache the first IP
            cache.insert(domain, ipAddresses[0]);
            cache.save();
        } else {
            std::cerr << "⚠️ No IP addresses found in response for " << domain << std::endl;
        }
    }

    return 0;
}
