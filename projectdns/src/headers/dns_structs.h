#ifndef DNS_STRUCTS_H
#define DNS_STRUCTS_H
#pragma once

#include <cstdint>

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

#endif // DNS_STRUCTS_H