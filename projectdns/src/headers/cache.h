#ifndef CACHE_H
#define CACHE_H
#pragma once

#include <string>
#include <unordered_map>

class DNSCache {
public:
    DNSCache(const std::string& filepath);

    void load();
    void save();
    void insert(const std::string& domain, const std::string& ip);
    bool contains(const std::string& domain) const;
    std::string get(const std::string& domain) const;

private:
    std::string filepath;
    std::unordered_map<std::string, std::string> cache;
};

#endif // CACHE_H