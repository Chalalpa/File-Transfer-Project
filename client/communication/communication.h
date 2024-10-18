#pragma once

#include <string>

#include "utils.h"

// Receives a socket and a username, and registers the username to the server.
// Returns - the returned uuid by the server (empty string if it failed).
std::string apply_registration(boost::asio::ip::tcp::socket& sock, const std::string& username);

// Receives a socket, me_info object and a string representing a private rsa
// key. Sends the private rsa key to the server, as the private key for this
// user. Returns - the generated aes key (empty string if it failed).
std::string exchange_public_rsa_key(boost::asio::ip::tcp::socket& sock,
                                    const me_info& me_info_details,
                                    const std::string& pub_key);

// Receives a socket and me_info object, and send a reconnection request to the
// server. Returns - the generated aes key (empty string if it failed).
std::string apply_reconnection(boost::asio::ip::tcp::socket& sock, const me_info& me_info_details);

// Receives a socket, a filepath, a string representing an aes key and me_info
// object. Encrypts the given file, and sends it to the server (in chunks).
// Returns - the calculated cksum by the server (zero if it failed).
uint32_t send_file(boost::asio::ip::tcp::socket& sock,
                   const std::string& file_path,
                   const std::string& aes_key,
                   const me_info& me_info_details);

// Receives a socket, a crc that was calculated for the file by the server, a
// file path, me_info object and current retries num. Checks if the crc
// calculated by the server matches our expectation. If it does - sends a
// matching request to the server. If not - sends a different request to the
// server. Returns - true if another retry is needed, and false if not.
bool handle_crc_response(boost::asio::ip::tcp::socket& sock,
                         const uint32_t server_crc,
                         const std::string& file_path,
                         const me_info& me_info_details,
                         const unsigned int retries_num);
