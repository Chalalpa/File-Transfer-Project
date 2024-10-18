#pragma once

#include <string>
#include <vector>

// Receives a size_t number and a size_t length.
// Returns - an std::vector<unsigned char> representing the num in <length>
// bytes.
std::vector<unsigned char> num_to_little_endian(const size_t num, const size_t length);

// Receives an std::vector<unsigned char> representing a little endian number.
// Returns - a uint32_t represented by the given vector
uint32_t little_endian_to_uint32(const std::vector<unsigned char>& vec);

// Receives a string with zero bytes padding.
// Returns - a stripped string (without the padding).
std::string strip_padding(const std::string& str);

// Receives an std::vector<unsigned char>.
// Returns - a string representing the bytes in the given vector in hexadecimal.
std::string vector_to_hex_str(const std::vector<unsigned char>& vec);

// Receives a string representing a hexadecimal sequence.
// Returns - an std::vector<unsigned char> of bytes representing the given
// string.
std::vector<unsigned char> hex_string_to_bytes(const std::string& hex_string);
