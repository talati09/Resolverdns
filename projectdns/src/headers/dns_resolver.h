#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <netinet/in.h> // <-- Add this line for sockaddr_in

#include "dns_structs.h"

class DNSResolver {
public:
    DNSResolver(const std::string &hostname);
    bool sendQuery();
    bool receiveResponse(std::vector<uint8_t> &responseBuffer);
    void printRawResponse(const std::vector<uint8_t> &buffer) const;
    void printDNSHeaderInfo(const std::vector<uint8_t>& buffer) const; // <-- Add this line
    void printQueryBuffer(const std::vector<uint8_t>& buffer) const; // <-- Add this line

private:
    void setupSocket();
    std::vector<uint8_t> buildQuery(const std::string &hostname);

    std::string hostname;
    int sockfd;
    struct sockaddr_in server_addr;
};
