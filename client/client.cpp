#include <iostream>
#include <optional>

#include <boost/asio.hpp>

#include "common/crypto.h"

#include "communication/communication.h"
#include "communication/constants.h"

// Examine simple client-server communication with the following main program
int main()
{
    // Read and parse transfer info file to figure out the connection details for
    // our client
    std::optional<connection_details> conn_details;
    try {
        std::cout << "Client: parsing transfer info file.." << std::endl;
        conn_details = parse_transfer_info();
    } catch (const std::exception& e) {
        std::cout << "Client: failed parsing transfer info file: " << e.what() << std::endl;
        std::cout << "Client: exiting due to an error.." << std::endl;
        return 1;
    }

    // Create a connection based on the read transfer file
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::socket sock(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints =
        resolver.resolve(conn_details->m_server_ip, conn_details->m_server_port);
    boost::asio::connect(sock, endpoints);

    // Exchange keys with the server
    std::optional<me_info> me_info_details;
    std::string encrypted_aes_key = "";
    try {
        std::cout << "Client: trying to parse me info file.." << std::endl;
        me_info_details = parse_me_info();
        std::cout << "Client: Attempting reconnection.." << std::endl;
        encrypted_aes_key = apply_reconnection(sock, *me_info_details);
    } catch (const std::exception& e) { // Failed parsing me info -> user is not registered
        std::cout << "Client: note that parsing me.info file has failed due to: " << e.what()
                  << std::endl;
        std::cout << "Client: user " << conn_details->m_username
                  << " is not registered. Sending registration request." << std::endl;
        std::string uuid = apply_registration(sock, conn_details->m_username);

        if (uuid.empty()) {
            std::cout << "Client: exiting due to registration failure.." << std::endl;
            return 1;
        }

        auto pub_key = generate_rsa_keys();
        const auto b64_private_rsa_key = base64_encode_rsa_private_key(load_private_key());

        if (b64_private_rsa_key.empty()) {
            std::cout << "Client: exiting due to rsa private key base64 encoding failure.."
                      << std::endl;
            return 1;
        }

        me_info_details = me_info(conn_details->m_username, uuid, b64_private_rsa_key);
        encrypted_aes_key = exchange_public_rsa_key(sock, *me_info_details, pub_key);

        if (!encrypted_aes_key.empty()) { // Save to file only after keys exchange success
            try {
                std::cout << "Client: saving me_info details to file.." << std::endl;
                me_info_details->save_to_file();
            } catch (const std::exception& e) {
                std::cout << "Client: failed saving me_info details to file: " << e.what()
                          << std::endl;
                std::cout << "Client: exiting.." << std::endl;
                return 1;
            }
        }
    }

    if (encrypted_aes_key.empty()) {
        std::cout << "Client: failed exchanging public rsa key" << std::endl;
        std::cout << "Client: exiting.." << std::endl;
        return 1;
    }

    const auto aes_key = decrypt_using_private_rsa(encrypted_aes_key, load_private_key());
    if (aes_key.empty()) {
        std::cout << "Client: failed decrypting aes key" << std::endl;
        std::cout << "Client: exiting.." << std::endl;
        return 1;
    }

    // Send file
    std::cout << "Client: sending file to server.." << std::endl;
    auto cksum = send_file(sock, conn_details->m_file_path, aes_key, *me_info_details);
    ;
    if (cksum == 0) {
        std::cout << "Client: failed transferring file" << std::endl;
        std::cout << "Client: exiting.." << std::endl;
        return 1;
    }

    // Handle received crc
    try {
        unsigned int i = 0;
        while (handle_crc_response(sock, cksum, conn_details->m_file_path, *me_info_details, i)) {
            ++i;
            std::cout << "Client: received wrong cksum from server for file "
                      << conn_details->m_file_path << ". "
                      << "Retrying.. (retry number " << i << ")" << std::endl;
            cksum = send_file(sock, conn_details->m_file_path, aes_key, *me_info_details);
        }
        if (i >= 2) { // Because we started from 0
            std::cout << "Client: failed transferring file " << conn_details->m_file_path
                      << ": calculated crc in server does not match client's side crc. "
                      << std::endl;
        } else {
            std::cout << "Client: file " << conn_details->m_file_path
                      << " was successfully transferred to server" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "Client: something went wrong in crc validation process: " << e.what()
                  << std::endl;
        return 1;
    }

    return 0;
}
