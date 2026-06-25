// main.cpp
#include "headers/dns_resolver.h"
#include "headers/parser.h"
#include "headers/cache.h"
#include "headers/utils.h"
#include "headers/dns_structs.h"
#include <iostream>
#include <string>
#include <vector>
#include <set>

// ─────────────────────────────────────────────
// PHASE 4: iterativeResolve
//
// This is the core of the project. Instead of asking 8.8.8.8 to do
// everything, we walk the DNS hierarchy ourselves:
//
//   Root Server → TLD Server → Authoritative Server → Final IP
//
// How it works at each step:
//   1. Send query to current server
//   2. Parse response into ParsedResponse
//   3. If we got an A record answer → done, return the IP
//   4. If we got a CNAME → re-query with the canonical name
//   5. If we got NS records with glue IPs → query that nameserver next
//   6. If we got NS records WITHOUT glue → resolve the NS hostname first
//      (recursive sub-problem), then query that IP
//   7. If nothing useful → give up
//
// maxHops prevents infinite loops in case of misconfigured DNS zones
// ─────────────────────────────────────────────
std::string iterativeResolve(
    const std::string& hostname,
    const std::vector<std::string>& rootServers,
    int hopCount = 0
) {
    const int maxHops = 20; // safety limit — real resolution never needs more than ~5
    if (hopCount > maxHops) {
        std::cerr << "❌ Max hops reached — possible loop detected for " << hostname << std::endl;
        return "";
    }

    // ── Step 1: Start from root servers ──
    // Try each root server until one responds
    std::string currentServerIP = "";
    std::vector<uint8_t> responseBuffer;

    std::cout << "\n[Hop " << hopCount + 1 << "] Starting from root servers for: " << hostname << std::endl;

    for (const std::string& rootIP : rootServers) {
        DNSResolver resolver(hostname, rootIP);
        if (!resolver.sendQuery()) continue;
        if (resolver.receiveResponse(responseBuffer)) {
            currentServerIP = rootIP;
            break;
        }
        std::cout << "   ⏭️  No response from " << rootIP << ", trying next root...\n";
    }

    if (currentServerIP.empty()) {
        std::cerr << "❌ No root server responded." << std::endl;
        return "";
    }

    // ── Main iterative loop ──
    // Each iteration queries one server and decides where to go next
    std::set<std::string> visited; // track visited servers to prevent loops

    while (true) {
        // Parse what the current server told us
        DNSParser parser;
        ParsedResponse result = parser.parseResponse(responseBuffer);

        // ── Case 1: Got a direct A record answer ──
        if (result.hasAnswer()) {
            std::cout << "   ✅ Got answer from " << currentServerIP
                      << ": " << result.answers[0] << std::endl;
            return result.answers[0];
        }

        // ── Case 2: Got a CNAME (alias) ──
        // Need to restart resolution with the canonical name
        if (result.hasCname()) {
            std::cout << "   🔗 CNAME found: " << hostname
                      << " → " << result.cname << std::endl;
            std::cout << "   ↩️  Restarting resolution for: " << result.cname << std::endl;
            // Recursively resolve the canonical name from scratch
            return iterativeResolve(result.cname, rootServers, hopCount + 1);
        }

        // ── Case 3: Got NS records — need to follow delegation ──
        if (!result.hasNameservers()) {
            std::cerr << "❌ No useful records from " << currentServerIP << std::endl;
            return "";
        }

        // Try each nameserver in the delegation list
        bool foundNextServer = false;

        for (const std::string& ns : result.nameservers) {
            std::string nextServerIP = "";

            // ── Case 3a: Glue record available — use it directly ──
            // The current server included the IP of this nameserver
            // in the Additional section. No extra lookup needed.
            if (result.glue.count(ns)) {
                nextServerIP = result.glue.at(ns);
                std::cout << "   📡 Delegated to: " << ns
                          << " (glue IP: " << nextServerIP << ")" << std::endl;
            }
            // ── Case 3b: No glue — need to resolve the NS hostname first ──
            // This is the tricky case. We need the IP of ns1.google.com
            // but to get it we need to do a separate full DNS resolution.
            // This is a recursive sub-problem.
            else {
                std::cout << "   📡 Delegated to: " << ns
                          << " (no glue — resolving NS hostname...)" << std::endl;
                nextServerIP = iterativeResolve(ns, rootServers, hopCount + 1);
            }

            if (nextServerIP.empty()) continue; // couldn't resolve this NS — try next
            if (visited.count(nextServerIP))    continue; // already tried this server

            visited.insert(nextServerIP);

            // Query the next nameserver in the chain
            std::cout << "   📤 Querying " << ns
                      << " (" << nextServerIP << ") for " << hostname << std::endl;

            DNSResolver nextResolver(hostname, nextServerIP);
            if (!nextResolver.sendQuery()) continue;

            if (nextResolver.receiveResponse(responseBuffer)) {
                currentServerIP = nextServerIP;
                foundNextServer = true;
                break; // got a response — continue the main loop with this response
            }

            std::cout << "   ⏭️  No response from " << nextServerIP << ", trying next NS...\n";
        }

        if (!foundNextServer) {
            std::cerr << "❌ All nameservers exhausted for " << hostname << std::endl;
            return "";
        }

        // Loop continues — parse the new response from the next server
    }
}

int main() {
    std::string hostname;
    std::cout << "Enter the hostname to resolve: ";
    std::cin >> hostname;

    // BUG 5 FIXED (Phase 1): was hardcoded Windows path "e:/projectdns/..."
    DNSCache cache("../src/data/cache.json");
    cache.load();

    // ── Cache check ──
    if (cache.contains(hostname)) {
        std::cout << "✅ [Cache HIT] IP for " << hostname
                  << ": " << cache.get(hostname) << std::endl;
        return 0;
    }

    std::cout << "🔍 [Cache MISS] Resolving " << hostname
              << " using iterative resolution...\n";

    // ── Load root servers ──
    std::vector<std::string> rootServers = loadRootServers("../src/data/root_servers.txt");
    if (rootServers.empty()) {
        std::cerr << "❌ No root servers loaded. Cannot resolve.\n";
        return 1;
    }

    // ── PHASE 4: Full iterative resolution ──
    std::string resolvedIP = iterativeResolve(hostname, rootServers);

    if (resolvedIP.empty()) {
        std::cerr << "❌ Failed to resolve: " << hostname << std::endl;
        return 1;
    }

    // ── Print and cache the result ──
    std::cout << "\n🎉 Final answer: " << hostname
              << " → " << resolvedIP << std::endl;
    cache.insert(hostname, resolvedIP);
    std::cout << "💾 Cached: " << resolvedIP << std::endl;

    return 0;
}