#include "../headers/cache.h"
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

DNSCache::DNSCache(const std::string& filename) : cacheFilePath(filename) {}

void DNSCache::load() {
    std::cout << "Trying to open cache file: " << cacheFilePath << std::endl; // Add this line
    std::ifstream infile(cacheFilePath);

    if (!infile.is_open()) {
        std::cerr << "❌ Could not open cache file for reading.\n";
        return;
    }

    try {
        json j;
        infile >> j;

        for (const auto& [domain, ip] : j.items()) {
            cache[domain] = ip;
        }
    } catch (const std::exception& e) {
        std::cerr << "❌ Error reading cache file: " << e.what() << std::endl;
    }
}

void DNSCache::save() {
    std::cout << "Trying to write cache file: " << cacheFilePath << std::endl; // Add this line
    std::ofstream outfile(cacheFilePath);

    if (!outfile.is_open()) {
        std::cerr << "❌ Could not open cache file for writing.\n";
        return;
    }

    json j;
    for (const auto& [domain, ip] : cache) {
        j[domain] = ip;
    }

    outfile << j.dump(4);
}

bool DNSCache::contains(const std::string& domain) const {
    return cache.find(domain) != cache.end();
}

std::string DNSCache::get(const std::string& domain) const {
    auto it = cache.find(domain);
    if (it != cache.end()) {
        return it->second;
    }
    return "";
}

void DNSCache::insert(const std::string& domain, const std::string& ip) {
    cache[domain] = ip;
    save();
}

void DNSCache::update(const std::string& domain, const std::string& ip) {
    cache[domain] = ip;
    save();
}

// ✅ Added aliases to fix build error in main.cpp and test_runner.cpp
bool DNSCache::isCached(const std::string& domain) const {
    return contains(domain);
}

std::string DNSCache::getIP(const std::string& domain) const {
    return get(domain);
}
