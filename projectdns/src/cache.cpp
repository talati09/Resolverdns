// cache.cpp
#include "../headers/cache.h"
#include "../external/nlohmann/json.hpp"
#include <fstream>
#include <iostream>

using json = nlohmann::json;

DNSCache::DNSCache(const std::string& filepath) : filepath(filepath) {}

void DNSCache::load() {
    std::ifstream infile(filepath);
    if (!infile.is_open()) {
        // File doesn't exist yet — that's fine, first run
        return;
    }

    try {
        // BUG 7 FIXED: previously jumped straight to parsing
        // If cache.json was empty, infile >> j would throw and get silently swallowed
        // Now we check file size first before attempting to parse
        infile.seekg(0, std::ios::end);
        if (infile.tellg() == 0) {
            return; // File is empty — nothing to load, not an error
        }
        infile.seekg(0, std::ios::beg);

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
    std::ofstream outfile(filepath);
    if (!outfile.is_open()) {
        std::cerr << "❌ Failed to open cache file for writing: " << filepath << std::endl;
        return;
    }

    json j = cache;
    outfile << j.dump(4); // pretty print with 4-space indent
}

void DNSCache::insert(const std::string& domain, const std::string& ip) {
    cache[domain] = ip;
    save();
}

bool DNSCache::contains(const std::string& domain) const {
    return cache.find(domain) != cache.end();
}

std::string DNSCache::get(const std::string& domain) const {
    auto it = cache.find(domain);
    if (it != cache.end()) return it->second;
    return "";
}