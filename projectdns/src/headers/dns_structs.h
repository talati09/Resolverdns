#ifndef DNS_STRUCTS_H
#define DNS_STRUCTS_H
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>

#define DNS_BUFFER_SIZE 512

// pragma pack(1) tells compiler: NO padding bytes between fields
// Without this, the compiler adds padding for alignment and the
// 12-byte DNS header becomes 16 bytes — breaking binary parsing
#pragma pack(push, 1)
struct DNSHeader {
    uint16_t id;       // Random ID to match query with response
    uint16_t flags;    // QR, OPCODE, AA, TC, RD, RA, RCODE bits
    uint16_t qdcount;  // Number of questions
    uint16_t ancount;  // Number of answers
    uint16_t nscount;  // Number of authority records
    uint16_t arcount;  // Number of additional records
};
#pragma pack(pop)

// ─────────────────────────────────────────────
// PHASE 2 ADDITION
// ParsedResponse holds the full picture of a DNS response —
// not just the final answer, but also which nameservers to ask
// next (for iterative resolution in Phase 4) and their glue IPs.
// ─────────────────────────────────────────────
struct ParsedResponse {
    // Answer section — final IPs if the server had a direct answer
    std::vector<std::string> answers;

    // Authority section — NS records: hostnames of nameservers to ask next
    std::vector<std::string> nameservers;

    // Additional section — glue records: nameserver hostname -> its IP
    // (saves us a separate lookup to resolve the nameserver's own IP)
    std::map<std::string, std::string> glue;

    // CNAME chain — if the domain was an alias, the canonical name to re-query
    std::string cname;

    bool hasAnswer() const { return !answers.empty(); }
    bool hasNameservers() const { return !nameservers.empty(); }
    bool hasCname() const { return !cname.empty(); }
};

#endif // DNS_STRUCTS_H