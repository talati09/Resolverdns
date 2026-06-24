// dns_resolver.cpp
#include "../headers/dns_resolver.h"
#include "../headers/dns_structs.h"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

// PHASE 3 CHANGE: constructor takes serverIP parameter
DNSResolver::DNSResolver(const std::string& hostname, const std::string& serverIP)
    : hostname(hostname), serverIP(serverIP) {
    setupSocket();
}

// BUG 2 FIXED (Phase 1): destructor closes the socket
DNSResolver::~DNSResolver() {
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
}

// PHASE 3 CHANGE: uses this->serverIP instead of hardcoded "8.8.8.8"
void DNSResolver::setupSocket() {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "❌ Failed to create socket." << std::endl;
        exit(EXIT_FAILURE);
    }

    // BUG 1 FIXED (Phase 1): 5 second receive timeout
    struct timeval tv;
    tv.tv_sec  = 5;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "❌ Failed to set socket timeout." << std::endl;
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(53);

    // PHASE 3: use serverIP — no longer hardcoded
    if (inet_pton(AF_INET, serverIP.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "❌ Invalid DNS server address: " << serverIP << std::endl;
        exit(EXIT_FAILURE);
    }
}

// DOUBLE HTONS BUG FIXED:
// pushUint16 already writes big-endian — never call htons before passing to it
void DNSResolver::buildQuery() {
    queryBuffer.clear();

    auto pushUint16 = [&](uint16_t val) {
        queryBuffer.push_back((val >> 8) & 0xFF);
        queryBuffer.push_back(val & 0xFF);
    };

    // Header
    pushUint16(0x1234); // ID
    pushUint16(0x0100); // FLAGS: RD=1
    pushUint16(1);      // QDCOUNT
    pushUint16(0);      // ANCOUNT
    pushUint16(0);      // NSCOUNT
    pushUint16(0);      // ARCOUNT

    // QNAME: encode "google.com" → \x06google\x03com\x00
    std::string label;
    std::string h = hostname + ".";
    for (char c : h) {
        if (c == '.') {
            queryBuffer.push_back((uint8_t)label.size());
            for (char lc : label) queryBuffer.push_back((uint8_t)lc);
            label.clear();
        } else {
            label += c;
        }
    }
    queryBuffer.push_back(0x00);

    pushUint16(1); // QTYPE  = A record
    pushUint16(1); // QCLASS = Internet
}

bool DNSResolver::sendQuery() {
    buildQuery();

    std::cout << "📤 Querying " << serverIP << " for " << hostname << std::endl;

    ssize_t sent = sendto(
        sockfd,
        queryBuffer.data(),
        queryBuffer.size(),
        0,
        (struct sockaddr*)&server_addr,
        sizeof(server_addr)
    );

    if (sent < 0) {
        std::cerr << "❌ Failed to send DNS query to " << serverIP << std::endl;
        return false;
    }
    return true;
}

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
        std::cerr << "❌ No response from " << serverIP << " (timeout or error)" << std::endl;
        return false;
    }

    responseBuffer.resize(received);
    return true;
}