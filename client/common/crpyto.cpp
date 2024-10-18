#include <iostream>

#include "crypto.h"

std::string base64_encode(const byte* buffer, size_t length)
{
    std::string encoded;
    Base64Encoder encoder(new StringSink(encoded), false); // Avoid line breaks
    encoder.Put(buffer, length);
    encoder.MessageEnd();
    return encoded;
}

// RSA
std::string generate_rsa_keys()
{
    // Generate RSA keys
    AutoSeededRandomPool rng;

    // Generate the private key
    RSA::PrivateKey private_key;
    private_key.GenerateRandomWithKeySize(rng, rsa_key_bits_size);

    // Save the private key to a file
    FileSink private_key_file(private_key_file_path.c_str());
    private_key.Save(private_key_file);

    // Generate the public key from the private key and return it
    RSAFunction public_key(private_key);
    std::string key;
    StringSink ss(key);
    public_key.Save(ss);

    return key;
}

RSA::PrivateKey load_private_key()
{
    RSA::PrivateKey private_key;
    FileSource private_key_file(private_key_file_path.c_str(), true);
    private_key.Load(private_key_file);

    return private_key;
}

std::string base64_encode_rsa_private_key(const RSA::PrivateKey& private_key)
{
    try {
        // Encode the private key to DER format
        ByteQueue queue;
        private_key.Save(queue);

        // Convert the ByteQueue to a byte array
        std::string der_encoded;
        StringSink sink(der_encoded);
        queue.TransferTo(sink);

        // Base64 encode the DER-encoded key
        return base64_encode(reinterpret_cast<const byte*>(der_encoded.data()), der_encoded.size());
    } catch (const Exception&) {
        return "";
    }
}

std::string decrypt_using_private_rsa(const std::string& encrypted_hex,
                                      const RSA::PrivateKey& private_key)
{
    AutoSeededRandomPool rng;
    std::string decrypted, binary_ciphertext;

    // Step 1: Decode the hex string to binary
    StringSource ss_hex(encrypted_hex, true, new HexDecoder(new StringSink(binary_ciphertext)));

    // Step 2: Decrypt the binary ciphertext
    RSAES_OAEP_SHA_Decryptor d(private_key);
    StringSource ss_cipher(binary_ciphertext,
                           true,
                           new PK_DecryptorFilter(rng, d, new StringSink(decrypted)));

    return decrypted;
}

std::vector<unsigned char> get_raw_public_key(const RSA::PublicKey& public_key)
{
    // Create a string to hold the X.509 encoded public key
    std::string x509_key;

    // Create a StringSink to write to the string
    StringSink ss(x509_key);
    public_key.DEREncode(ss);

    // Convert the string to a vector of unsigned char
    std::vector<unsigned char> raw_x509_key(x509_key.begin(), x509_key.end());

    // Return the X.509 encoded public key as a vector
    return raw_x509_key;
}

// AES
bool is_valid_aes_key(const std::string& key)
{
    return key.size() == (aes_key_bits_size / 8);
}

std::string encrypt_using_aes(const std::string& data, const std::string& key)
{
    if (!is_valid_aes_key(key)) {
        throw std::runtime_error("Error: given key is not a valid AES key");
    }

    // We are assuming IV is always set to zeros
    byte iv[AES::BLOCKSIZE] = { 0 };

    // Create an AES object with the given key
    AES::Encryption aes_encryption((byte*)key.data(), key.size());

    // Create a cipher in CBC mode
    CBC_Mode<AES>::Encryption cbc_encryption(reinterpret_cast<const byte*>(key.data()),
                                             key.size(),
                                             iv);

    std::string encrypted_str;

    // Encrypt the data
    StringSource(data,
                 true,
                 new StreamTransformationFilter(cbc_encryption, new StringSink(encrypted_str)));

    return encrypted_str;
}
