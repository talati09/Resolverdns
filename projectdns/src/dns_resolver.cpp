// dns_resolver.cpp
#include "../headers/dns_resolver.h"
#include "../headers/dns_structs.h"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

// ─────────────────────────────────────────────
// Constructor — stores hostname, sets up socket
// ─────────────────────────────────────────────
DNSResolver::DNSResolver(const std::string& hostname) {
    this->hostname = hostname;
    setupSocket();
}

// ─────────────────────────────────────────────
// Destructor
// BUG 2 FIXED: socket was opened in setupSocket() but close() was never called
// This is a resource leak — the OS keeps the socket open until program exits
// The fix: always close the socket when the DNSResolver object is destroyed
// ─────────────────────────────────────────────
DNSResolver::~DNSResolver() {
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
}

// ─────────────────────────────────────────────
// setupSocket — creates a UDP socket and points it at 8.8.8.8:53
// ─────────────────────────────────────────────
void DNSResolver::setupSocket() {
    // AF_INET = IPv4, SOCK_DGRAM = UDP, 0 = default protocol
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "❌ Failed to create socket." << std::endl;
        exit(EXIT_FAILURE);
    }

    // BUG 1 FIXED: previously no timeout was set on recvfrom()
    // If the DNS server never replied, the program hung forever
    // Fix: set a 5-second receive timeout using SO_RCVTIMEO
    struct timeval tv;
    tv.tv_sec  = 5;  // 5 second timeout
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "❌ Failed to set socket timeout." << std::endl;
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(53); // DNS port

    // Currently hardcoded to Google's public DNS
    // In Phase 4 this will become a parameter so we can query root/TLD servers
    if (inet_pton(AF_INET, "127.0.0.53", &server_addr.sin_addr) <= 0) {
        std::cerr << "❌ Invalid DNS server address." << std::endl;
        exit(EXIT_FAILURE);
    }
}

// ─────────────────────────────────────────────
// buildQuery — manually constructs a raw DNS query packet byte by byte
//
// Packet layout:
//   [Header 12 bytes] [Question: QNAME + QTYPE + QCLASS]
//
// QNAME encoding: each label is prefixed with its length
//   "google.com" → \x06google\x03com\x00
// ─────────────────────────────────────────────
void DNSResolver::buildQuery() {
    queryBuffer.clear();

    // ── Header ──
    uint16_t id      = 0x1234; // fixed ID for now (random would be better)
    uint16_t flags   = 0x0100; // QR=0 (query), RD=1 (recursion desired)
    uint16_t qdcount = 1;      // 1 question
    uint16_t zero    = 0;

    auto pushUint16 = [&](uint16_t val) {
        queryBuffer.push_back((val >> 8) & 0xFF);
        queryBuffer.push_back(val & 0xFF);
    };

    pushUint16(id);
    pushUint16(flags);
    pushUint16(qdcount);
    pushUint16(zero); // ancount
    pushUint16(zero); // nscount
    pushUint16(zero); // arcount

    // ── QNAME: encode "google.com" as \x06google\x03com\x00 ──
    std::string label;
    std::string h = hostname + "."; // add trailing dot to simplify parsing
    for (char c : h) {
        if (c == '.') {
            queryBuffer.push_back((uint8_t)label.size()); // length prefix
            for (char lc : label) queryBuffer.push_back((uint8_t)lc);
            label.clear();
        } else {
            label += c;
        }
    }
    queryBuffer.push_back(0x00); // null terminator

    // ── QTYPE = 1 (A record), QCLASS = 1 (Internet) ──
    pushUint16(1); // QTYPE
    pushUint16(1); // QCLASS
}

// ─────────────────────────────────────────────
// sendQuery — builds the packet and fires it over UDP
// ─────────────────────────────────────────────
bool DNSResolver::sendQuery() {
    buildQuery();
    ssize_t sent = sendto(
        sockfd,
        queryBuffer.data(),
        queryBuffer.size(),
        0,
        (struct sockaddr*)&server_addr,
        sizeof(server_addr)
    );

    if (sent < 0) {
        std::cerr << "❌ Failed to send DNS query." << std::endl;
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────
// receiveResponse — waits for response and fills responseBuffer
// Will now timeout after 5 seconds instead of hanging forever (Bug 1 fix)
// ─────────────────────────────────────────────
bool DNSResolver::receiveResponse(std::vector<uint8_t>& responseBuffer) {
    responseBuffer.resize(DNS_BUFFER_SIZE);
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    ssize_t received = recvfrom(
        sockfd,
        responseBuffer.data(),
        DNS_BUFFER_SIZE,
        0,
        (struct sockaddr*)&from_addr,
        &from_len
    );

    if (received < 0) {
        std::cerr << "❌ Failed to receive DNS response (timeout or network error)." << std::endl;
        return false;
    }

    responseBuffer.resize(received);
    return true;
}