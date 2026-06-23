#ifndef UTILS_H
#define UTILS_H
#pragma once

#include <string>
#include <vector>
#include <cstdint>

// Converts vector of 4 bytes into dotted IP string (e.g. 93.184.216.34)
std::string formatIPAddress(const std::vector<uint8_t>& bytes);

// Dumps a byte buffer in hex format (useful for debugging)
std::string hexDump(const std::vector<uint8_t>& data);

// PHASE 3 ADDITION:
// Reads root_servers.txt and returns a vector of root server IP strings
// File format expected:  198.41.0.4    A.ROOT-SERVERS.NET
// Returns only the IPs (left column), ignores the names (right column)
std::vector<std::string> loadRootServers(const std::string& filepath);

#endif // UTILS_H