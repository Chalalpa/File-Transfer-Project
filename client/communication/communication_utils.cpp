#include <fstream>
#include <iostream>
#include <optional>
#include <filesystem>

#include <aes.h>
#include <base64.h>
#include <crc.h>
#include <cryptlib.h>
#include <files.h>
#include <hex.h>
#include <modes.h>
#include <osrng.h>
#include <rsa.h>
#include <secblock.h>

#include "../common/utils.h"

#include "constants.h"
#include "utils.h"

// connection_details
connection_details::connection_details(std::string server_ip,
                                       std::string server_port,
                                       std::string file_path,
                                       std::string username) :
    m_server_ip(server_ip),
    m_server_port(server_port),
    m_file_path(file_path),
    m_username(username)
{}

connection_details parse_transfer_info()
{
    std::ifstream transfer_info_fh(transfer_info_file_path);
    if (!transfer_info_fh.is_open()) { // Make sure we are able to open the file for read
        throw std::runtime_error("Error: could not open " + transfer_info_file_path +
                                 " transfer info file");
    }

    std::string line;
    int line_index = 0;

    std::string server_ip = "";
    std::string server_port = "";
    std::string file_path = "";
    std::string username = "";

    while (std::getline(transfer_info_fh, line)) {
        switch (line_index) {
        case server_ip_port_line_index:
        {
            std::stringstream ss(line);
            if (!std::getline(ss, server_ip, ':') || !(ss >> server_port)) {
                throw std::runtime_error("Error: could not parse 'ip:port' from line " + line);
            }
            break;
        }
        case transfer_username_line_index:
        {
            username = std::move(line);
            if (username.size() > username_max_size) {
                throw std::runtime_error("Error: max size for username input should be " +
                                         std::to_string(username_max_size) + " chars");
            }
            break;
        }
        case file_to_transfer_line_index:
        {
            file_path = std::move(line);
            if (!std::filesystem::exists(file_path)) {
                throw std::runtime_error("Error: file to transfer '" + file_path +
                                         "' does not exist!");
            }
            break;
        }
        default:
            break; // We are only interested in the first lines
        }
        ++line_index;
    }

    return connection_details { server_ip, server_port, file_path, username };
}

// me_info
me_info::me_info(std::string username, std::string uuid, std::string private_key) :
    m_username(username),
    m_uuid(uuid),
    m_private_key(private_key)
{}

me_info parse_me_info()
{
    std::ifstream me_info_fh(me_info_file_path);
    if (!me_info_fh.is_open()) { // Make sure we are able to open the file for read
        throw std::runtime_error("Error: could not open '" + me_info_file_path + "' me info file");
    }

    std::string line;
    int line_index = 0;

    std::string username = "";
    std::string uuid = "";
    std::string private_key = "";
    bool stop_iterating = false;

    while (std::getline(me_info_fh, line) && !stop_iterating) {
        switch (line_index++) {
        case me_username_line_index:
            username = std::move(line);
            if (username.size() > username_max_size) {
                throw std::runtime_error("Error: max size for username input should be " +
                                         std::to_string(username_max_size) + " chars");
            }
            break;
        case uuid_line_index:
            uuid = std::move(line);
            if (uuid.size() != uuid_length * 2) {
                throw std::runtime_error("Error: uuid length must be " +
                                         std::to_string(uuid_length * 2));
            }
            break;
        case private_key_line_index:
            private_key = std::move(line);
            break;
        default:
            stop_iterating = true; // We are only interested in the first lines
            break;
        }
    }

    return me_info { username, uuid, private_key };
}

void me_info::save_to_file() const
{
    std::ofstream me_info_fh(me_info_file_path);

    if (!me_info_fh.is_open()) { // Make sure we are able to open the file for read
        throw std::runtime_error("Error: could not open '" + me_info_file_path + "' me info file");
    }

    me_info_fh << m_username << std::endl;
    me_info_fh << m_uuid << std::endl;
    me_info_fh << m_private_key << std::endl;

    me_info_fh.close();
}

// response_header
response_header::response_header(const std::vector<unsigned char>& header_buffer) :
    m_version(header_buffer[0]),
    m_res_code((header_buffer[1] << 8) | header_buffer[2]),
    m_payload_size((header_buffer[3] << 24) | (header_buffer[4] << 16) | (header_buffer[5] << 8) |
                   header_buffer[6])
{}

response::response(response_header res_header, std::vector<unsigned char> payload) :
    m_response_header(std::move(res_header)),
    m_payload(std::move(payload))
{}

void response_header::to_little_endian()
{
    // Swap bytes for m_res_code
    m_res_code = (m_res_code >> 8) | (m_res_code << 8);

    // Swap bytes for m_payload_size
    m_payload_size = ((m_payload_size >> 24) & 0x000000FF) | ((m_payload_size >> 8) & 0x0000FF00) |
                     ((m_payload_size << 8) & 0x00FF0000) | ((m_payload_size << 24) & 0xFF000000);
}

std::vector<unsigned char> build_request_header(const std::string& uuid,
                                                const uint16_t req_code,
                                                const uint32_t payload_size)
{
    std::vector<unsigned char> req_header = hex_string_to_bytes(uuid);

    req_header.push_back(client_ver);
    auto req_code_little_endian = num_to_little_endian(req_code, request_code_field_length);
    req_header.insert(req_header.end(),
                      req_code_little_endian.begin(),
                      req_code_little_endian.end()); // Insert request code

    auto payload_size_little_endian = num_to_little_endian(payload_size, payload_size_field_length);
    req_header.insert(req_header.end(),
                      payload_size_little_endian.begin(),
                      payload_size_little_endian.end()); // Insert payload size

    return req_header;
}

response receive_response(boost::asio::ip::tcp::socket& sock)
{
    std::vector<unsigned char> header_buffer(version_field_length + response_code_field_length +
                                             payload_size_field_length);

    // Read raw bytes
    boost::asio::read(sock, boost::asio::buffer(header_buffer.data(), header_buffer.size()));

    response_header header { header_buffer };

    // Convert header values to little-endian format
    header.to_little_endian();

    std::vector<unsigned char> payload(header.m_payload_size);
    boost::asio::read(sock, boost::asio::buffer(payload.data(), header.m_payload_size));

    response res { header, payload };

    return res;
}

response send_req_wait_res(boost::asio::ip::tcp::socket& sock, const std::vector<unsigned char> req)
{
    size_t attempts = 0;
    std::optional<response> res;
    do {
        ++attempts;
        boost::asio::write(sock, boost::asio::buffer(req));
        res = receive_response(sock);
        if (res->m_response_header.m_res_code == response_code::general_error) {
            std::cout << "server responded with an error";
        }
    } while (attempts <= 3 && res->m_response_header.m_res_code == response_code::general_error);

    if (res->m_response_header.m_res_code == response_code::general_error) {
        std::cout << "Client: got general error from server, exiting.." << std::endl;
        exit(1);
    }

    return res.value();
}
