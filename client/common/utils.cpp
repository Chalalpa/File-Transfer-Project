#include <iomanip>
#include <iostream>

#include <boost/algorithm/hex.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>

#include "utils.h"

std::vector<unsigned char> num_to_little_endian(const size_t num, const size_t length)
{
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < length; ++i) { // Insert content size (after encryption)
        bytes.push_back(static_cast<unsigned char>((num >> (i * 8)) & 0xFF));
    }

    return bytes;
}

uint32_t little_endian_to_uint32(const std::vector<unsigned char>& vec)
{
    uint32_t num = 0;
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        num |= static_cast<uint32_t>(vec[i]) << (i * 8);
    }

    return num;
}

std::string strip_padding(const std::string& str)
{
    std::string stripped_str = "";
    auto null_pos = std::find(str.begin(), str.end(), static_cast<unsigned char>(0));
    if (null_pos != str.end()) {
        stripped_str = std::string(str.begin(), null_pos);
    } else {
        stripped_str = std::string(str.begin(), str.end());
    }

    return stripped_str;
}

std::vector<unsigned char> hex_string_to_bytes(const std::string& hex_string)
{
    std::vector<unsigned char> bytes;

    try {
        boost::algorithm::unhex(hex_string.begin(), hex_string.end(), std::back_inserter(bytes));
    } catch (const boost::algorithm::hex_decode_error& e) {
        std::cout << "Invalid hex string: " << e.what() << std::endl;
        throw;
    }

    return bytes;
}

std::string vector_to_hex_str(const std::vector<unsigned char>& vec)
{
    std::ostringstream oss; // Create a string stream to build the string
    for (unsigned char byte : vec) {
        // Output each byte as a two-digit hexadecimal number
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str(); // Return the accumulated string
}
