// dns_resolver.cpp
#include "../headers/dns_resolver.h"
#include "../headers/dns_structs.h"

#include <iostream>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

// Constructor
DNSResolver::DNSResolver(const std::string &hostname) {
    this->hostname = hostname;
    setupSocket();
}

// Setup UDP socket to 8.8.8.8
void DNSResolver::setupSocket() {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "❌ Failed to create socket." << std::endl;
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);

    if (inet_pton(AF_INET, "8.8.8.8", &server_addr.sin_addr) <= 0) {
        std::cerr << "❌ Invalid DNS server IP address." << std::endl;
        exit(EXIT_FAILURE);
    }
}

// Construct DNS query for hostname
std::vector<uint8_t> DNSResolver::buildQuery(const std::string &hostname) {
    std::vector<uint8_t> queryBuffer;
    queryBuffer.reserve(512);

    // DNS Header
    DNSHeader header;
    header.id = htons(rand() % 65536);
    header.flags = htons(0x0100); // recursion desired
    header.qdcount = htons(1);
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    queryBuffer.insert(
        queryBuffer.end(),
        reinterpret_cast<uint8_t*>(&header),
        reinterpret_cast<uint8_t*>(&header) + sizeof(DNSHeader)
    );

    // QNAME
    std::istringstream iss(hostname);
    std::string label;
    while (std::getline(iss, label, '.')) {
        queryBuffer.push_back(static_cast<uint8_t>(label.length()));
        for (char c : label) {
            queryBuffer.push_back(static_cast<uint8_t>(c));
        }
    }
    queryBuffer.push_back(0);

    // QTYPE and QCLASS
    uint16_t qtype = htons(1);   // A record
    uint16_t qclass = htons(1);  // IN class
    queryBuffer.insert(queryBuffer.end(), reinterpret_cast<uint8_t*>(&qtype), reinterpret_cast<uint8_t*>(&qtype) + 2);
    queryBuffer.insert(queryBuffer.end(), reinterpret_cast<uint8_t*>(&qclass), reinterpret_cast<uint8_t*>(&qclass) + 2);

    return queryBuffer;
}

// Send DNS query
bool DNSResolver::sendQuery() {
    std::vector<uint8_t> queryBuffer = buildQuery(hostname);

    ssize_t bytesSent = sendto(
        sockfd,
        queryBuffer.data(),
        queryBuffer.size(),
        0,
        (const struct sockaddr *)&server_addr,
        sizeof(server_addr)
    );

    if (bytesSent < 0) {
        std::cerr << "❌ Failed to send DNS query." << std::endl;
        return false;
    }

    return true;
}

// Print DNS header info and RCODE for debugging
void DNSResolver::printDNSHeaderInfo(const std::vector<uint8_t>& buffer) const {
    if (buffer.size() < sizeof(DNSHeader)) {
        std::cerr << "Buffer too small for DNS header." << std::endl;
        return;
    }
    const DNSHeader* header = reinterpret_cast<const DNSHeader*>(buffer.data());
    uint16_t id = ntohs(header->id);
    uint16_t flags = ntohs(header->flags);
    uint16_t qdcount = ntohs(header->qdcount);
    uint16_t ancount = ntohs(header->ancount);
    uint8_t rcode = flags & 0x000F;
    std::cout << "[DNS Header] ID=" << id
              << " FLAGS=0x" << std::hex << flags << std::dec
              << " QD=" << qdcount
              << " ANS=" << ancount
              << " RCODE=" << static_cast<int>(rcode) << std::endl;
}

// Receive DNS response
bool DNSResolver::receiveResponse(std::vector<uint8_t> &responseBuffer) {
    responseBuffer.resize(DNS_BUFFER_SIZE);

    ssize_t bytesReceived = recvfrom(
        sockfd,
        responseBuffer.data(),
        responseBuffer.size(),
        0,
        nullptr,
        nullptr
    );

    if (bytesReceived <= 0) {
        std::cerr << "❌ Failed to receive DNS response." << std::endl;
        return false;
    }

    responseBuffer.resize(bytesReceived);

    // Print DNS header info and RCODE for debugging
    printDNSHeaderInfo(responseBuffer);

    return true;
}

// Optional: Print raw response in hex
void DNSResolver::printRawResponse(const std::vector<uint8_t> &buffer) const {
    std::cout << "\n[+] Raw DNS Response (Hex Dump):\n";
    for (size_t i = 0; i < buffer.size(); ++i) {
        printf("%02X ", buffer[i]);
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    std::cout << std::endl;
}

void DNSResolver::printQueryBuffer(const std::vector<uint8_t>& buffer) const {
    std::cout << "[Query Buffer] ";
    for (size_t i = 0; i < buffer.size(); ++i) {
        printf("%02X ", buffer[i]);
    }
    std::cout << std::endl;
}