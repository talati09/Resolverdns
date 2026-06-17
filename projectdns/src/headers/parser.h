#ifndef PARSER_H
#define PARSER_H
#pragma once

#include <string>
#include <vector>
#include <cstdint>

class DNSParser {
public:
    // BUG 3 FIXED: was declared 'static' but internally creates a DNSParser
    // object to call non-static methods (readName, readUint16, readUint32)
    // — that is a contradiction. Removed 'static'.
    std::vector<std::string> parseResponse(const std::vector<uint8_t>& buffer);

private:
    std::string readName(const std::vector<uint8_t>& buffer, size_t& offset);
    uint16_t readUint16(const std::vector<uint8_t>& buffer, size_t& offset);
    uint32_t readUint32(const std::vector<uint8_t>& buffer, size_t& offset);
};

#endif // PARSER_H