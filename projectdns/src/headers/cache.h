#pragma once

#include <string>
#include <unordered_map>

class DNSCache {
public:
    DNSCache(const std::string& path);

    void load();
    void save();
    void insert(const std::string& domain, const std::string& ip);
    void update(const std::string& domain, const std::string& ip);  // ✅ Add this
    bool contains(const std::string& domain) const;
    std::string get(const std::string& domain) const;
    bool isCached(const std::string& domain) const;
std::string getIP(const std::string& domain) const;

private:
    std::string cacheFilePath;
    std::unordered_map<std::string, std::string> cache;
};
