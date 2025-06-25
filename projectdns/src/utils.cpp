// utils.cpp
#include "../headers/utils.h"
#include <cstdint>
#include <sstream>
#include <iomanip>

// Convert raw IP bytes to dotted string format (e.g. 192.168.1.1)
std::string formatIPAddress(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) oss << ".";
        oss << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

// Hex dump of raw bytes, useful for debugging
std::string hexDump(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (size_t i = 0; i < data.size(); ++i) {
        if (i % 16 == 0)
            oss << "\n" << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
        oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i]) << " ";
    }
    return oss.str();
}
