#pragma once

#include <iostream>
#include <string>

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

using namespace CryptoPP;

// crypto related constants
static std::string private_key_file_path = "priv.key";
static constexpr int rsa_key_bits_size = 1024;
static constexpr int aes_key_bits_size = 256;

// Base64
std::string base64_encode(const byte* buffer, size_t length);

// RSA

// Generates private rsa key and stores it into `private_key_file_path`.
// Returns - a string representing the public RSA key.
std::string generate_rsa_keys();

// Loads the private key from `private_key_file_path`.
// Returns - an RSA::PrivateKey representing the loaded key.
RSA::PrivateKey load_private_key();

// Receives an RSA::PrivateKey object.
// Returns - a string representing a base64 encode of the given private rsa key.
std::string base64_encode_rsa_private_key(const RSA::PrivateKey& private_key);

// Receives a string representing an encrypted hexadecimal sequence, and an
// RSA::PrivateKey object. Returns - a string representing the decrypted output
// of that given encrypted_hex.
std::string decrypt_using_private_rsa(const std::string& encrypted_hex,
                                      const RSA::PrivateKey& private_key);

// Receives an RSA::PublicKey object.
// Returns - an std::vector<unsigned char> representing the public key
std::vector<unsigned char> get_raw_public_key(const RSA::PublicKey& public_key);

// AES

// Receives a string representing an AES key.
// Returns - true if the given AES key is valid, false if not.
bool is_valid_aes_key(const std::string& key);

// Receives a string representing data, and another string representing an AES
// key. Returns - a string representing the data after encryption with the given
// AES key.
std::string encrypt_using_aes(const std::string& data, const std::string& key);
