// parser.cpp
#include "../headers/parser.h"
#include "../headers/dns_structs.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>  

// ─────────────────────────────────────────────
// readUint16 — reads 2 bytes big-endian from buffer at offset, advances offset
// ─────────────────────────────────────────────
uint16_t DNSParser::readUint16(const std::vector<uint8_t>& buffer, size_t& offset) {
    uint16_t value = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    return value;
}

// ─────────────────────────────────────────────
// readUint32 — reads 4 bytes big-endian from buffer at offset, advances offset
// ─────────────────────────────────────────────
uint32_t DNSParser::readUint32(const std::vector<uint8_t>& buffer, size_t& offset) {
    uint32_t value = ((uint32_t)buffer[offset] << 24) |
                     ((uint32_t)buffer[offset+1] << 16) |
                     ((uint32_t)buffer[offset+2] << 8)  |
                     (uint32_t)buffer[offset+3];
    offset += 4;
    return value;
}

// ─────────────────────────────────────────────
// readName — reads a DNS-encoded domain name from buffer at offset
//
// DNS names are encoded as length-prefixed labels:
//   google.com → \x06google\x03com\x00
//
// Pointer compression: if top 2 bits of a byte are 11 (i.e. byte & 0xC0 == 0xC0)
// it's a pointer, not a label. The next byte gives the offset to jump to.
//
// BUG 4 FIXED:
//   - Added bounds checking (offset >= buffer.size()) to prevent out-of-bounds reads
//   - Added maxJumps guard (10 hops max) to prevent infinite loops from
//     malicious or malformed packets
//   - originalOffset is now correctly saved ONLY on the FIRST pointer jump
//     and restored after all jumps are done
// ─────────────────────────────────────────────
std::string DNSParser::readName(const std::vector<uint8_t>& buffer, size_t& offset) {
    std::string name;
    size_t originalOffset = 0;
    bool jumped = false;
    size_t jumps = 0;
    const size_t maxJumps = 10; // safety cap — real DNS doesn't chain more than a few

    while (true) {
        if (offset >= buffer.size()) break; // bounds check

        uint8_t len = buffer[offset];

        if ((len & 0xC0) == 0xC0) {
            // ── Pointer ──
            // Top 2 bits are 11 → this is a compression pointer, not a label
            if (offset + 1 >= buffer.size()) break; // bounds check

            if (!jumped) {
                // Save where to return ONLY on the very first jump
                // offset + 2 skips past the 2-byte pointer itself
                originalOffset = offset + 2;
            }

            // Extract the 14-bit offset value
            uint16_t pointer = ((len & 0x3F) << 8) | buffer[offset + 1];
            offset = pointer;
            jumped = true;

            if (++jumps > maxJumps) break; // malicious packet guard
            continue;
        }

        if (len == 0) {
            // ── Null terminator — end of name ──
            if (!jumped) offset++; // advance past null byte only if we haven't jumped
            break;
        }

        // ── Regular label ──
        offset++; // skip the length byte
        if (!name.empty()) name += ".";
        if (offset + len > buffer.size()) break; // bounds check
        name += std::string(buffer.begin() + offset, buffer.begin() + offset + len);
        offset += len;
    }

    if (jumped) {
        offset = originalOffset; // restore to position right after the pointer bytes
    }

    return name;
}

// ─────────────────────────────────────────────
// parseResponse — parses a raw DNS response buffer and returns all A record IPs
//
// BUG 3 FIXED: this was declared 'static' in the header but created a DNSParser
// object internally to call non-static methods — a contradiction.
// 'static' has been removed from the declaration in parser.h
// ─────────────────────────────────────────────
std::vector<std::string> DNSParser::parseResponse(const std::vector<uint8_t>& buffer) {
    std::vector<std::string> ipAddresses;

    if (buffer.size() < sizeof(DNSHeader)) {
        std::cerr << "❌ Response too short to contain a DNS header." << std::endl;
        return ipAddresses;
    }

    // ── Read header ──
    size_t offset = 0;
    DNSHeader header;
    memcpy(&header, buffer.data(), sizeof(DNSHeader));
    offset += sizeof(DNSHeader);

    uint16_t ancount = ntohs(header.ancount); // number of answer records
    uint16_t qdcount = ntohs(header.qdcount); // number of questions

    // ── Skip Question section ──
    // The response echoes back our question — we need to skip it
    for (int i = 0; i < qdcount; i++) {
        readName(buffer, offset); // skip QNAME
        offset += 4;              // skip QTYPE (2 bytes) + QCLASS (2 bytes)
    }

    // ── Read Answer section ──
    for (int i = 0; i < ancount; i++) {
        readName(buffer, offset); // skip NAME (domain name, often a pointer)

        uint16_t type     = readUint16(buffer, offset); // record type
        uint16_t rclass   = readUint16(buffer, offset); // class (always 1 = Internet)
        uint32_t ttl      = readUint32(buffer, offset); // time-to-live (unused for now)
        uint16_t rdlength = readUint16(buffer, offset); // length of RDATA

        (void)rclass; // suppress unused variable warning
        (void)ttl;    // TTL will be used in Phase 5 for cache expiry

        if (type == 1 && rdlength == 4) {
            // ── A record — IPv4 address ──
            // RDATA is exactly 4 bytes: one per octet of the IP address
            if (offset + 4 <= buffer.size()) {
                std::ostringstream ip;
                ip << (int)buffer[offset]     << "."
                   << (int)buffer[offset + 1] << "."
                   << (int)buffer[offset + 2] << "."
                   << (int)buffer[offset + 3];
                ipAddresses.push_back(ip.str());
            }
        }
        offset += rdlength; // skip past RDATA regardless of type
    }

    return ipAddresses;
}