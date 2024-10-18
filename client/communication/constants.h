#pragma once

#include <string>

namespace request_code
{
static constexpr uint16_t registration = 825;
static constexpr uint16_t public_key_exchange = 826;
static constexpr uint16_t reconnection_attempt = 827;
static constexpr uint16_t file_transfer = 828;
static constexpr uint16_t valid_crc = 900;
static constexpr uint16_t invalid_crc_retry = 901;
static constexpr uint16_t invalid_crc_done = 902;
} // namespace request_code

namespace response_code
{
static constexpr uint16_t registration_success = 1600;
static constexpr uint16_t registration_failure = 1601;
static constexpr uint16_t public_key_accepted_aes_exchange = 1602;
static constexpr uint16_t valid_file_with_crc = 1603;
static constexpr uint16_t message_ack =
    1604; // Could be a response for INVALID_CRC_RETRY, INVALID_CRC_DONE
static constexpr uint16_t reconnection_public_key_accepted_aes_exchange = 1605;
static constexpr uint16_t reconnection_rejected = 1606;
static constexpr uint16_t general_error = 1607;
} // namespace response_code

// transfer info file constants
static std::string transfer_info_file_path = "transfer.info";
static constexpr int server_ip_port_line_index = 0;
static constexpr int transfer_username_line_index = 1;
static constexpr int file_to_transfer_line_index = 2;
static constexpr int username_max_size = 100;

// me info file constants
static std::string me_info_file_path = "me.info";
static constexpr int me_username_line_index = 0;
static constexpr int uuid_line_index = 1;
static constexpr int private_key_line_index = 2;

// file transfer related constants
static constexpr unsigned int file_transfer_retries_num = 3;
static constexpr unsigned int file_transfer_chunk_size = 2048; // This is an arbitrary choice

// communication constants
static constexpr unsigned char client_ver = 3;
static constexpr unsigned char server_ver = 3;

static constexpr unsigned char general_error_retries_num = 3;

// response header
static constexpr unsigned int response_code_field_length = 2;
static constexpr unsigned int request_code_field_length = 2;
static constexpr unsigned int version_field_length = 1;
static constexpr unsigned int payload_size_field_length = 4;

static constexpr unsigned int name_field_length = 255;
static constexpr unsigned int pub_key_field_length = 160;
static constexpr unsigned int content_size_field_length = 4;
static constexpr unsigned int orig_file_size_field_length = 4;
static constexpr unsigned int packet_number_field_length = 2;
static constexpr unsigned int total_packets_field_length = 2;
static constexpr unsigned int file_name_field_length = 255;
static constexpr unsigned int cksum_field_length = 4;
static constexpr unsigned int uuid_length = 16;
