// parser.cpp
#include "../headers/parser.h"
#include "../headers/dns_structs.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>  // Added for ntohs/ntohl

std::vector<std::string> DNSParser::parseResponse(const std::vector<uint8_t>& buffer) {
    std::cout << "[+] parseResponse called with buffer size: " << buffer.size() << " bytes\n";
    size_t offset = 0;

    // Step 1: Parse DNS Header
    DNSHeader header;
    std::memcpy(&header, buffer.data(), sizeof(DNSHeader));
    offset += sizeof(DNSHeader);

    header.id = ntohs(header.id);
    header.flags = ntohs(header.flags);
    header.qdcount = ntohs(header.qdcount);
    header.ancount = ntohs(header.ancount);
    header.nscount = ntohs(header.nscount);
    header.arcount = ntohs(header.arcount);

    std::cout << "Header: ID=" << header.id << " QD=" << header.qdcount << " ANS=" << header.ancount << "\n";

    std::vector<std::string> ipAddresses;  // <== Added

    DNSParser parser;  // <== Added to call member functions

    // Step 2: Skip the Question section
    for (int i = 0; i < header.qdcount; ++i) {
        std::string qname = parser.readName(buffer, offset);
        offset += 4; // Skip QTYPE + QCLASS
    }

    // Step 3: Parse the Answer section
    for (int i = 0; i < header.ancount; ++i) {
        std::string name = parser.readName(buffer, offset);
        uint16_t type = parser.readUint16(buffer, offset);
        uint16_t class_ = parser.readUint16(buffer, offset);
        uint32_t ttl = parser.readUint32(buffer, offset);
        uint16_t rdlength = parser.readUint16(buffer, offset);

        if (type == 1 && class_ == 1 && rdlength == 4) { // A record (IPv4)
            std::ostringstream ip;
            ip << static_cast<int>(buffer[offset]) << "."
               << static_cast<int>(buffer[offset + 1]) << "."
               << static_cast<int>(buffer[offset + 2]) << "."
               << static_cast<int>(buffer[offset + 3]);

            ipAddresses.push_back(ip.str());  // <== Added to return
            std::cout << "[+] A Record for " << name << ": " << ip.str() << " (TTL=" << ttl << ")\n";
        }
        offset += rdlength;
    }

    return ipAddresses;  // <== Added
}

std::string DNSParser::readName(const std::vector<uint8_t>& buffer, size_t& offset) {
    std::string name;
    size_t originalOffset = offset;
    bool jumped = false;

    while (true) {
        uint8_t len = buffer[offset];

        if ((len & 0xC0) == 0xC0) {
            uint16_t pointer = ((len & 0x3F) << 8) | buffer[offset + 1];
            if (!jumped) originalOffset = offset + 2;
            offset = pointer;
            jumped = true;
            continue;
        }

        if (len == 0) {
            if (!jumped) offset++;
            break;
        }

        offset++;
        if (!name.empty()) name += ".";
        name += std::string(buffer.begin() + offset, buffer.begin() + offset + len);
        offset += len;
    }

    if (!jumped) return name;
    else {
        offset = originalOffset;
        return name;
    }
}

uint16_t DNSParser::readUint16(const std::vector<uint8_t>& buffer, size_t& offset) {
    uint16_t value = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    return value;
}

uint32_t DNSParser::readUint32(const std::vector<uint8_t>& buffer, size_t& offset) {
    uint32_t value = (buffer[offset] << 24) |
                     (buffer[offset + 1] << 16) |
                     (buffer[offset + 2] << 8) |
                     buffer[offset + 3];
    offset += 4;
    return value;
}
