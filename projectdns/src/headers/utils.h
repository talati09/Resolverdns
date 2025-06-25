// utils.h
#ifndef UTILS_H
#define UTILS_H
#pragma once
#include <string>
#include <vector>
#include <cstdint> 

// Converts vector of 4 bytes into IP string (e.g. 93.184.216.34)
std::string formatIPAddress(const std::vector<uint8_t>& bytes);

// Dumps a byte buffer in hex format (useful for debugging)
std::string hexDump(const std::vector<uint8_t>& data);

#endif // UTILS_H
