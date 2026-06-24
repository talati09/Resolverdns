// utils.cpp
#include "../headers/utils.h"
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <iostream>

// Convert raw IP bytes to dotted string format (e.g. 192.168.1.1)
std::string formatIPAddress(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) oss << ".";
        oss << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

// Hex dump of raw bytes — useful for debugging raw DNS packets
std::string hexDump(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (size_t i = 0; i < data.size(); ++i) {
        if (i % 16 == 0)
            oss << "\n" << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
        oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i]) << " ";
    }
    return oss.str();
}

// ─────────────────────────────────────────────
// PHASE 3: loadRootServers
// Reads root_servers.txt which looks like this:
//   198.41.0.4        A.ROOT-SERVERS.NET
//   199.9.14.201      B.ROOT-SERVERS.NET
//
// We only need the IP (first column).
// Returns a vector of IP strings ready to query directly.
// ─────────────────────────────────────────────
std::vector<std::string> loadRootServers(const std::string& filepath) {
    std::vector<std::string> servers;
    std::ifstream infile(filepath);

    if (!infile.is_open()) {
        std::cerr << "❌ Could not open root servers file: " << filepath << std::endl;
        return servers;
    }

    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string ip, name;

        if (iss >> ip >> name) {
            if (!ip.empty()) {
                servers.push_back(ip);
            }
        }
    }

    if (servers.empty()) {
        std::cerr << "⚠️  No root servers loaded from: " << filepath << std::endl;
    } else {
        std::cout << "✅ Loaded " << servers.size() << " root servers." << std::endl;
    }

    return servers;
}