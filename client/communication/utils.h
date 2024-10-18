#pragma once

#include <vector>

#include <boost/algorithm/hex.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

struct connection_details
{
    connection_details(std::string server_ip,
                       std::string server_port,
                       std::string file_path,
                       std::string username);

    std::string m_server_ip;
    std::string m_server_port;
    std::string m_file_path;
    std::string m_username;
};

struct me_info
{
    me_info(std::string username, std::string uuid, std::string private_key);

    void save_to_file() const;

    std::string m_username;
    std::string m_uuid;
    std::string m_private_key;
};

struct response_header
{
    response_header(const std::vector<unsigned char>& header_buffer);

    uint8_t m_version;
    uint16_t m_res_code;
    uint32_t m_payload_size;

    void to_little_endian();
};

struct response
{
    response(response_header res_header, std::vector<unsigned char> payload);

    response_header m_response_header;
    std::vector<unsigned char> m_payload;
};

// Parses the transfer info file.
// Returns - a connection_details struct object representing the parsed file.
connection_details parse_transfer_info();

// Parses the me info file.
// Returns - a me_info struct object representing the parsed file.
me_info parse_me_info();

// Receives a uuid string, a request code (uint16_t) and a payload size
// (uint32_t). Returns - a vector representing the header of the request, built
// using the given params.
std::vector<unsigned char> build_request_header(const std::string& uuid,
                                                const uint16_t req_code,
                                                const uint32_t payload_size);

// Receives a socket object.
// Returns - a response struct object, representing the response given by the
// server from listening to the socket.
response receive_response(boost::asio::ip::tcp::socket& sock);

// Receives a socket object and a vector of chars that represents the requests.
// Returns - a response struct object, representing the response given by the
// server from listening to the socket.
// Note that this function retries up to <max retries num> if it faces a general server error
response send_req_wait_res(boost::asio::ip::tcp::socket& sock,
                           const std::vector<unsigned char> req);
