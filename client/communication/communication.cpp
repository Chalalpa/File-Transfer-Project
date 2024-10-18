#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <chrono>

#include <boost/algorithm/hex.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>

#include "../common/cksum.h"
#include "../common/crypto.h"
#include "../common/utils.h"

#include "communication.h"
#include "constants.h"
#include "utils.h"

void verify_res_version(const response& res)
{
    if (res.m_response_header.m_version != server_ver) {
        throw std::runtime_error("version in response from server does not match expected");
    }
}

std::string apply_registration(boost::asio::ip::tcp::socket& sock, const std::string& username)
{
    std::string uuid = "";
    try {
        std::string fake_uuid = "00000000000000000000000000000000"; // uuid for registration request
                                                                    // should be ignored
        auto req = build_request_header(fake_uuid, request_code::registration, name_field_length);

        // Build payload
        std::vector<unsigned char> name_bytes(name_field_length,
                                              0); // Initialize with 0 (null padding)
        std::memcpy(name_bytes.data(), username.c_str(), username.size());
        req.insert(req.end(), name_bytes.begin(), name_bytes.end());

        auto res = send_req_wait_res(sock, req);
        verify_res_version(res);
        if (res.m_response_header.m_res_code != response_code::registration_success) {
            if (res.m_response_header.m_res_code == response_code::registration_failure) {
                std::cout << "Client: failed to register username " << username
                          << " due to registration failure "
                          << "(res code: " << res.m_response_header.m_res_code << ")." << std::endl;
            } else {
                std::cout << "Client: failed to register username " << username
                          << ". Received unexpected res code: " << res.m_response_header.m_res_code
                          << std::endl;
            }
        } else { // Registration success
            uuid = vector_to_hex_str(res.m_payload);
            std::cout << "Client: Registration was successful. Received uuid: " << uuid
                      << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "Client: failed to register username " << username << ": " << e.what()
                  << std::endl;
    }

    return uuid;
}

std::string exchange_public_rsa_key(boost::asio::ip::tcp::socket& sock,
                                    const me_info& me_info_details,
                                    const std::string& pub_key)
{
    std::string aes_key = "";
    try {
        // Build header
        auto req = build_request_header(me_info_details.m_uuid,
                                        request_code::public_key_exchange,
                                        name_field_length + pub_key_field_length);

        // Build payload
        std::vector<unsigned char> name_bytes(name_field_length,
                                              0); // Initialize with 0 (null padding)
        std::memcpy(name_bytes.data(),
                    me_info_details.m_username.c_str(),
                    me_info_details.m_username.size());
        req.insert(req.end(), name_bytes.begin(), name_bytes.end());

        std::vector<unsigned char> pub_key_bytes(pub_key.begin(), pub_key.end());
        req.insert(req.end(), pub_key_bytes.begin(), pub_key_bytes.end());

        auto res = send_req_wait_res(sock, req);
        verify_res_version(res);

        if (res.m_response_header.m_res_code != response_code::public_key_accepted_aes_exchange) {
            if (res.m_response_header.m_res_code == response_code::reconnection_rejected) {
                std::cout << "Client: failed to exchange public key for uuid"
                          << me_info_details.m_uuid
                          << " (res code: " << res.m_response_header.m_res_code << ")."
                          << std::endl;
            } else {
                std::cout << "Client: failed to exchange public key for uuid"
                          << me_info_details.m_uuid
                          << ". Received unexpected res code: " << res.m_response_header.m_res_code
                          << std::endl;
            }
        } else { // Public key exchange success
            std::vector<unsigned char> returned_uuid(res.m_payload.begin(),
                                                     res.m_payload.begin() + uuid_length);
            auto hex_str_uuid = vector_to_hex_str(returned_uuid);
            if (vector_to_hex_str(returned_uuid) != me_info_details.m_uuid) {
                std::cout << "Client: public key exchange seemed to be successful, but "
                             "returned uuid was not expected. "
                             "Received: "
                          << hex_str_uuid << " while expected: " << me_info_details.m_uuid
                          << std::endl;
            } else {
                std::vector<unsigned char> returned_aes_key(res.m_payload.begin() + uuid_length,
                                                            res.m_payload.end());
                aes_key = vector_to_hex_str(returned_aes_key);
                std::cout << "Client: public key exchange was successful. Received aes_key: "
                          << aes_key << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cout << "Client: failed to exchange public key for uuid " << me_info_details.m_uuid
                  << ": " << e.what() << std::endl;
    }

    return aes_key;
}

std::string apply_reconnection(boost::asio::ip::tcp::socket& sock, const me_info& me_info_details)
{
    std::string aes_key = "";
    try {
        auto req = build_request_header(me_info_details.m_uuid,
                                        request_code::reconnection_attempt,
                                        name_field_length);

        // Build payload
        std::vector<unsigned char> name_bytes(name_field_length,
                                              0); // Initialize with 0 (null padding)
        std::memcpy(name_bytes.data(),
                    me_info_details.m_username.c_str(),
                    me_info_details.m_username.size());
        req.insert(req.end(), name_bytes.begin(), name_bytes.end());

        auto res = send_req_wait_res(sock, req);
        verify_res_version(res);

        if (res.m_response_header.m_res_code !=
            response_code::reconnection_public_key_accepted_aes_exchange) {
            if (res.m_response_header.m_res_code == response_code::reconnection_rejected) {
                std::cout << "Client: failed to reconnect uuid " << me_info_details.m_uuid
                          << "due to failure "
                          << "(res code: " << res.m_response_header.m_res_code << ")." << std::endl;
            } else {
                std::cout << "Client: failed to reconnect uuid " << me_info_details.m_uuid
                          << ". Received unexpected res code: " << res.m_response_header.m_res_code
                          << std::endl;
            }
        } else { // Reconnection success
            std::vector<unsigned char> returned_uuid(res.m_payload.begin(),
                                                     res.m_payload.begin() + uuid_length);
            auto hex_str_uuid = vector_to_hex_str(returned_uuid);
            if (vector_to_hex_str(returned_uuid) != me_info_details.m_uuid) {
                std::cout << "Client: Reconnection seemed to be successful, but "
                             "returned uuid was not expected. "
                             "Received: "
                          << hex_str_uuid << " while expected: " << me_info_details.m_uuid
                          << std::endl;
            } else {
                std::vector<unsigned char> returned_aes_key(res.m_payload.begin() + uuid_length,
                                                            res.m_payload.end());
                aes_key = vector_to_hex_str(returned_aes_key);
                std::cout << "Client: Reconnection was successful. Received aes_key: " << aes_key
                          << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cout << "Client: failed to reconnect for uuid " << me_info_details.m_uuid << ": "
                  << e.what() << std::endl;
    }

    return aes_key;
}

// Given a response of transfer success received by the server, verifies the
// returned uuid, filename and content size In comparison to the expected
// details. For internal purposes (not exposed).
bool verify_file_transfer_success_response(const response& res,
                                           const std::string& expected_uuid,
                                           const std::string& expected_filename,
                                           const size_t expected_content_size)
{
    // Get fields from response
    std::vector<unsigned char> returned_uuid(res.m_payload.begin(),
                                             res.m_payload.begin() + uuid_length);
    std::vector<unsigned char> returned_content_size(
        res.m_payload.begin() + uuid_length, // after encryption
        res.m_payload.begin() + uuid_length + content_size_field_length);
    std::string returned_file_name(
        res.m_payload.begin() + uuid_length + content_size_field_length,
        res.m_payload.begin() + uuid_length + content_size_field_length + file_name_field_length);

    const auto content_size = little_endian_to_uint32(returned_content_size);
    std::string str_filename = strip_padding(returned_file_name);
    auto hex_str_uuid = vector_to_hex_str(returned_uuid);

    // Verify returned values
    if (hex_str_uuid != expected_uuid) {
        std::cout << "Client: File transfer seemed to be successful, but returned "
                     "uuid was not expected. "
                     "Received: "
                  << hex_str_uuid << " while expected: " << expected_uuid << std::endl;
        return false;
    } else if (str_filename != expected_filename) {
        std::cout << "Client: File transfer seemed to be successful, but returned "
                     "filename was not expected. "
                     "Received: "
                  << str_filename << " while expected: " << expected_filename << std::endl;
        return false;
    } else if (content_size != expected_content_size) {
        std::cout << "Client: File transfer seemed to be successful, but returned "
                     "encrypted file size was "
                     "not expected. Received: "
                  << content_size << " while expected: " << expected_content_size << std::endl;
        return false;
    }

    return true;
}

uint32_t send_file(boost::asio::ip::tcp::socket& sock,
                   const std::string& file_path,
                   const std::string& aes_key,
                   const me_info& me_info_details)
{
    uint32_t received_crc = 0;
    try {
        std::ifstream fh(file_path, std::ios::binary);
        if (!fh.is_open()) { // Make sure we are able to open the file for read
            throw std::runtime_error("Error: could not open " + file_path + " file");
        }

        std::string buffer((std::istreambuf_iterator<char>(fh)), std::istreambuf_iterator<char>());
        std::string encrypted_buffer = encrypt_using_aes(buffer, aes_key);
        std::string filename =
            std::filesystem::path(file_path).filename().string(); // file basename

        for (size_t i = 0; i < encrypted_buffer.size(); i += file_transfer_chunk_size) {
            size_t size =
                std::min(static_cast<size_t>(file_transfer_chunk_size), encrypted_buffer.size() - i);
            std::vector<char> chunk(encrypted_buffer.begin() + i,
                                    encrypted_buffer.begin() + i + size);

            size_t payload_size = content_size_field_length + orig_file_size_field_length +
                                  packet_number_field_length + total_packets_field_length +
                                  file_name_field_length + size;
            auto req = build_request_header(me_info_details.m_uuid,
                                            request_code::file_transfer,
                                            payload_size);

            // Build payload
            auto little_endian =
                num_to_little_endian(encrypted_buffer.size(), content_size_field_length);
            req.insert(req.end(),
                       little_endian.begin(),
                       little_endian.end()); // Insert content size (after encryption)

            little_endian = num_to_little_endian(buffer.size(), content_size_field_length);
            req.insert(req.end(),
                       little_endian.begin(),
                       little_endian.end()); // Insert content size (before encryption)

            const auto packet_index = i / file_transfer_chunk_size + 1;
            little_endian = num_to_little_endian(packet_index, packet_number_field_length);
            req.insert(req.end(),
                       little_endian.begin(),
                       little_endian.end()); // Insert packet index

            uint16_t total_packets_num =
                (encrypted_buffer.size() + file_transfer_chunk_size - 1) / file_transfer_chunk_size;
            little_endian = num_to_little_endian(total_packets_num, total_packets_field_length);
            req.insert(req.end(),
                       little_endian.begin(),
                       little_endian.end()); // Insert total packets number

            std::vector<unsigned char> filename_bytes(file_name_field_length,
                                                      0); // Initialize with 0 (null padding)
            std::memcpy(filename_bytes.data(), filename.c_str(), filename.size());
            req.insert(req.end(), filename_bytes.begin(),
                       filename_bytes.end()); // Insert filename

            req.insert(req.end(), chunk.begin(), chunk.end()); // message content

            // Add a short sleep here to not mix up requests, as we are not
            // waiting for a response from server until the last packet.
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            boost::asio::write(sock, boost::asio::buffer(req));
        }
        response res = receive_response(sock);
        verify_res_version(res);

        if (res.m_response_header.m_res_code != response_code::valid_file_with_crc) {
            std::cout << "Client: failed to transfer file " << file_path
                      << ". Received unexpected res code: " << res.m_response_header.m_res_code
                      << std::endl;
        } else {
            if (verify_file_transfer_success_response(res,
                                                      me_info_details.m_uuid,
                                                      filename,
                                                      encrypted_buffer.size())) {
                std::vector<unsigned char> returned_cksum(res.m_payload.begin() + uuid_length +
                                                              content_size_field_length +
                                                              file_name_field_length,
                                                          res.m_payload.end());
                received_crc = little_endian_to_uint32(returned_cksum);
                std::cout << "Client: submitted file transfer successfully. Received cksum: "
                          << received_crc << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cout << "Client: file transfer failed for uuid " << me_info_details.m_uuid
                  << ", file path " << file_path << ": " << e.what() << std::endl;
    }

    return received_crc;
}

bool handle_crc_response(boost::asio::ip::tcp::socket& sock,
                         const uint32_t server_crc,
                         const std::string& file_path,
                         const me_info& me_info_details,
                         const unsigned int retries_num)
{
    uint32_t actual_crc = calculate_crc(file_path);
    std::cout << "Our checksum is: " << actual_crc << std::endl;
    const auto is_crc_valid = actual_crc == server_crc;
    const auto should_retry = !is_crc_valid && retries_num < file_transfer_retries_num;

    uint16_t req_code;
    if (is_crc_valid) {
        req_code = request_code::valid_crc;
    } else if (retries_num < file_transfer_retries_num) {
        req_code = request_code::invalid_crc_retry;
    } else {
        req_code = request_code::invalid_crc_done;
    }

    auto req = build_request_header(me_info_details.m_uuid, req_code, file_name_field_length);

    // Build payload
    std::string filename = std::filesystem::path(file_path).filename().string(); // file basename
    std::vector<unsigned char> file_name_bytes(file_name_field_length,
                                               0); // Initialize with 0 (null padding)
    std::memcpy(file_name_bytes.data(), filename.c_str(), filename.size());
    req.insert(req.end(), file_name_bytes.begin(), file_name_bytes.end());

    boost::asio::write(sock, boost::asio::buffer(req));

    // We are expecting a response from the server if the crc was valid, or was
    // invalid and we are done retrying
    if (req_code == request_code::valid_crc || req_code == request_code::invalid_crc_done) {
        response res = receive_response(sock);
        verify_res_version(res);

        if (res.m_response_header.m_res_code != response_code::message_ack) {
            throw std::runtime_error(
                "Client: Issue in server's response to CRC ack: returned "
                "response code: " +
                std::to_string(res.m_response_header.m_res_code) +
                " while expected: " + me_info_details.m_uuid);
        }

        std::string uuid = vector_to_hex_str(res.m_payload);
        if (uuid != me_info_details.m_uuid) {
            throw std::runtime_error(
                "Client: Issue in server's response to CRC ack: returned "
                "UUID was not expected. "
                "Received: " +
                uuid + " while expected: " + me_info_details.m_uuid);
        }
    }

    return should_retry;
}
