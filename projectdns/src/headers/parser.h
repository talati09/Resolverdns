#ifndef PARSER_H
#define PARSER_H

#include <string>
#include <vector>
#include <cstdint>

class DNSParser {
public:
    // Parses the raw DNS response and prints the extracted records (e.g., IPs)
    static std::vector<std::string> parseResponse(const std::vector<uint8_t>& buffer);

private:
    // Reads a domain name from a DNS response using pointer compression
    std::string readName(const std::vector<uint8_t>& buffer, size_t& offset);

    // Utility to safely extract 2-byte and 4-byte integers from the buffer
    uint16_t readUint16(const std::vector<uint8_t>& buffer, size_t& offset);
    uint32_t readUint32(const std::vector<uint8_t>& buffer, size_t& offset);
};

#endif // PARSER_H
