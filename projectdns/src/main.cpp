#include "../headers/dns_resolver.h"
#include "../headers/parser.h"
#include "../headers/cache.h"

#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <ctime>

int main() {
    std::srand(std::time(nullptr)); // Seed random for DNS query ID

    std::string hostname;
    std::cout << "Enter the hostname to resolve: ";
    std::cin >> hostname;

    DNSCache cache("e:/projectdns/data/cache.json");
    cache.load();

    if (cache.contains(hostname)) {
        std::cout << "✅ Cached IP for " << hostname << ": " << cache.get(hostname) << std::endl;
        return 0;
    }

    std::cout << "\n🔍 Resolving: " << hostname << "\n";

    DNSResolver resolver(hostname);

    if (!resolver.sendQuery()) {
        std::cerr << "❌ Failed to send query.\n";
        return 1;
    }

    std::vector<uint8_t> responseBuffer;
    if (!resolver.receiveResponse(responseBuffer)) {
        std::cerr << "❌ Failed to receive DNS response.\n";
        return 1;
    }

    resolver.printRawResponse(responseBuffer); // Optional

    DNSParser parser;
    std::vector<std::string> ipAddresses = parser.parseResponse(responseBuffer);

    if (ipAddresses.empty()) {
        std::cout << "⚠️ No A record IPs found in the response.\n";
    } else {
        for (const auto& ip : ipAddresses) {
            std::cout << "✅ Resolved IP: " << ip << std::endl;
            cache.insert(hostname, ip);
        }
    }

    return 0;
}
