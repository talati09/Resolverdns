// parser.cpp
#include "../headers/parser.h"
#include "../headers/dns_structs.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>  // needed for ntohs() / ntohl() — converts network byte order to host byte order

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
// parseResponse — parses a raw DNS response and returns a ParsedResponse
// containing Answer, Authority (NS), and Additional (glue) sections.
//
// PHASE 2 CHANGE:
//   - Now reads all 3 record sections, not just Answer
//   - Handles A (type 1), NS (type 2), and CNAME (type 5) records
//   - Authority section NS records tell us which server to ask next
//   - Additional section gives us the IP of that server directly (glue)
//
// BUG 3 FIX (from Phase 1) still applies: this is non-static because it
// needs the non-static readName/readUint16/readUint32 helpers.
// ─────────────────────────────────────────────
ParsedResponse DNSParser::parseResponse(const std::vector<uint8_t>& buffer) {
    ParsedResponse result;

    if (buffer.size() < sizeof(DNSHeader)) {
        std::cerr << "❌ Response too short to contain a DNS header." << std::endl;
        return result;
    }

    // ── Read header ──
    size_t offset = 0;
    DNSHeader header;
    memcpy(&header, buffer.data(), sizeof(DNSHeader));
    offset += sizeof(DNSHeader);

    uint16_t qdcount = ntohs(header.qdcount); // number of questions
    uint16_t ancount = ntohs(header.ancount); // number of answer records
    uint16_t nscount = ntohs(header.nscount); // number of authority (NS) records
    uint16_t arcount = ntohs(header.arcount); // number of additional records

    // ── Skip Question section ──
    // The response echoes back our question — we need to skip past it
    for (int i = 0; i < qdcount; i++) {
        readName(buffer, offset); // skip QNAME
        offset += 4;              // skip QTYPE (2 bytes) + QCLASS (2 bytes)
    }

    // ── Helper lambda: reads ONE resource record and routes it based on TYPE ──
    // Every record (Answer, Authority, Additional) shares this exact format:
    //   NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA
    // 'section' tells us where this record came from so we know where to store it.
    auto readRecord = [&](const std::string& section) {
        std::string name = readName(buffer, offset); // record owner name

        if (offset + 10 > buffer.size()) { // not enough bytes for TYPE+CLASS+TTL+RDLENGTH
            offset = buffer.size();
            return;
        }

        uint16_t type     = readUint16(buffer, offset); // record type
        uint16_t rclass   = readUint16(buffer, offset); // class (always 1 = Internet)
        uint32_t ttl      = readUint32(buffer, offset); // time-to-live (used in Phase 5)
        uint16_t rdlength = readUint16(buffer, offset); // length of RDATA

        (void)rclass; // suppress unused variable warning
        (void)ttl;    // TTL will be used in Phase 5 for cache expiry

        size_t rdataStart = offset; // remember where RDATA begins

        if (type == 1 && rdlength == 4) {
            // ── A record — IPv4 address (4 raw bytes, not name-encoded) ──
            if (offset + 4 <= buffer.size()) {
                std::ostringstream ip;
                ip << (int)buffer[offset]     << "."
                   << (int)buffer[offset + 1] << "."
                   << (int)buffer[offset + 2] << "."
                   << (int)buffer[offset + 3];

                if (section == "answer") {
                    result.answers.push_back(ip.str());
                } else if (section == "additional") {
                    // Glue record: maps the nameserver hostname (the NAME field
                    // of this record) to its IP address
                    result.glue[name] = ip.str();
                }
            }
        }
        else if (type == 2) {
            // ── NS record — RDATA is a domain-name-encoded nameserver hostname ──
            // Only meaningful in the Authority section
            size_t nsOffset = rdataStart; // readName needs its own offset cursor
            std::string nsHost = readName(buffer, nsOffset);
            if (section == "authority") {
                result.nameservers.push_back(nsHost);
            }
        }
        else if (type == 5) {
            // ── CNAME record — RDATA is a domain-name-encoded canonical name ──
            size_t cnOffset = rdataStart;
            std::string canonical = readName(buffer, cnOffset);
            if (section == "answer") {
                result.cname = canonical; // we'll need to re-query with this name
            }
        }

        // Always advance by rdlength regardless of type — this keeps the
        // offset correct even for record types we don't explicitly handle
        offset = rdataStart + rdlength;
    };

    // ── Read Answer section ──
    for (int i = 0; i < ancount; i++) {
        if (offset >= buffer.size()) break;
        readRecord("answer");
    }

    // ── Read Authority section (NS records — who to ask next) ──
    for (int i = 0; i < nscount; i++) {
        if (offset >= buffer.size()) break;
        readRecord("authority");
    }

    // ── Read Additional section (glue records — IPs of those nameservers) ──
    for (int i = 0; i < arcount; i++) {
        if (offset >= buffer.size()) break;
        readRecord("additional");
    }

    return result;
}