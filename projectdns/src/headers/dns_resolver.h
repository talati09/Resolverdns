#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <netinet/in.h>

class DNSResolver {
public:
    DNSResolver(const std::string& hostname);

    // BUG 2 FIXED: destructor added — socket was opened but never closed (resource leak)
    ~DNSResolver();

    bool sendQuery();
    bool receiveResponse(std::vector<uint8_t>& responseBuffer);

private:
    std::string hostname;
    int sockfd = -1;
    struct sockaddr_in server_addr;
    std::vector<uint8_t> queryBuffer;

    void setupSocket();
    void buildQuery();
};

#endif // DNS_RESOLVER_H