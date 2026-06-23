#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <netinet/in.h>

class DNSResolver {
public:
    // PHASE 3 CHANGE: accepts serverIP parameter so we can query any DNS server
    // Default is "127.0.0.53" so existing code keeps working
    DNSResolver(const std::string& hostname, const std::string& serverIP = "127.0.0.53");

    // BUG 2 FIXED (Phase 1): destructor added — socket was never closed
    ~DNSResolver();

    bool sendQuery();
    bool receiveResponse(std::vector<uint8_t>& responseBuffer);

private:
    std::string hostname;
    std::string serverIP;
    int sockfd = -1;
    struct sockaddr_in server_addr;
    std::vector<uint8_t> queryBuffer;

    void setupSocket();
    void buildQuery();
};

#endif // DNS_RESOLVER_H