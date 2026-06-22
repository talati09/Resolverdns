#ifndef PARSER_H
#define PARSER_H
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "dns_structs.h"

class DNSParser {
public:
    // PHASE 2 CHANGE: return type changed from vector<string> to ParsedResponse
    // Now returns Answer, Authority (NS), and Additional (glue) sections —
    // not just a flat list of IPs. This is needed for iterative resolution.
    ParsedResponse parseResponse(const std::vector<uint8_t>& buffer);

private:
    std::string readName(const std::vector<uint8_t>& buffer, size_t& offset);
    uint16_t readUint16(const std::vector<uint8_t>& buffer, size_t& offset);
    uint32_t readUint32(const std::vector<uint8_t>& buffer, size_t& offset);
};

#endif // PARSER_H