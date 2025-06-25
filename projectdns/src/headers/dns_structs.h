#ifndef DNS_STRUCTS_H
#define DNS_STRUCTS_H

#pragma once

#include <cstdint>

#define DNS_BUFFER_SIZE 512

#pragma pack(push, 1)
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

#endif // DNS_STRUCTS_H
