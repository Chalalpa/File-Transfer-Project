import socket
import struct
import os

from common.cksum import memcrc
from common.utils import logger
from common.crypto import generate_aes_key, encrypt_aes_key, decrypt_using_aes
from entities.file import File, FileDataError
from entities.user import UserDataError
from .constants import SERVER_VERSION, VERSION_SIZE, ENDIAN_TYPE, RESPONSE_CODE_SIZE, PAYLOAD_SIZE_SIZE, \
    REGISTRATION_FORMAT, ResponseCode, REGISTRATION_SUCCESS_FORMAT, KEY_EXCHANGE_FORMAT, RECONNECTION_REJECTED_FORMAT, \
    AES_KEY_SIZE, PUBLIC_KEY_ACCEPTED_AES_EXCHANGE_FORMAT, RECONNECTION_FORMAT, FILE_TRANSFER_METADATA_FORMAT, \
    FILE_TRANSFER_METADATA_SIZE, VALID_FILE_WITH_CRC_FORMAT, CONTENT_SIZE_SIZE, CHECKSUM_SIZE, CRC_REQUEST_FORMAT, \
    RequestCode, MESSAGE_ACK_FORMAT
from entities.users import Users
from entities.users_db import UsersDB

USERS_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'users_files')


def send_response(conn: socket.socket, res_code: int, data: bytes) -> None:
    """Sending a response using the given socket, with given data and response code"""
    payload_size = len(data)
    version_hex = SERVER_VERSION.to_bytes(VERSION_SIZE, byteorder=ENDIAN_TYPE)
    res_code_hex = res_code.to_bytes(RESPONSE_CODE_SIZE, byteorder=ENDIAN_TYPE)
    payload_size_hex = payload_size.to_bytes(PAYLOAD_SIZE_SIZE, byteorder=ENDIAN_TYPE)
    header = version_hex + res_code_hex + payload_size_hex
    conn.sendall(header + data)


def handle_registration(conn: socket.socket, payload: bytes, client_id: bytes) -> None:
    """Handling registration request from a client"""
    # Ignoring client_id as there's not much of a meaning for that in a registration
    username = struct.unpack(REGISTRATION_FORMAT, payload)[0].decode('utf-8').rstrip('\x00')  # remove padding bytes

    try:
        user_uuid = Users().register_user(username)
        send_response(conn, ResponseCode.REGISTRATION_SUCCESS, struct.pack(REGISTRATION_SUCCESS_FORMAT, user_uuid))
        logger.info(f"handle_registration: registration was successful for user {username}")
    except UserDataError as e:
        logger.warning(f"handle_registration: caught error: {e}")
        send_response(conn, ResponseCode.REGISTRATION_FAILURE, b"")
    except Exception as e:
        logger.warning(f"handle_registration: caught general error: {e}")
        send_response(conn, ResponseCode.GENERAL_ERROR, b"")


def handle_key_exchange(conn: socket.socket, payload: bytes, client_id: bytes) -> None:
    """Handling key exchange request from a client"""
    username, public_key = struct.unpack(KEY_EXCHANGE_FORMAT, payload)

    username = username.decode('utf-8').rstrip('\x00')
    public_key = public_key.rstrip(b'\x00')
    user = Users().get_user_by_username(username=username)

    if user is None or user.uuid != client_id:  # Verifying user's uuid matches what we received in the header
        logger.warning(f"handle_key_exchange: user does not exist or given client id ({client_id.hex()}) "
                       "doesn't match stored one")
        send_response(conn, ResponseCode.RECONNECTION_REJECTED, struct.pack(RECONNECTION_REJECTED_FORMAT, client_id))

    else:  # User exists
        # Save public key
        user.public_key = public_key
        # Create AES key and encrypt with RSA
        aes_key = generate_aes_key(AES_KEY_SIZE)
        user.aes_key = aes_key  # Store the aes key in the user object
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

        # Add user to DB, after we have aes key and public rsa key for the user
        UsersDB.add_user(user)

        send_response(conn, ResponseCode.PUBLIC_KEY_ACCEPTED_AES_EXCHANGE,
                      struct.pack(PUBLIC_KEY_ACCEPTED_AES_EXCHANGE_FORMAT, client_id) + encrypted_aes_key)
        logger.info(f"handle_key_exchange: successfully generated aes key for client id {client_id.hex()}")


def handle_reconnection(conn: socket.socket, payload: bytes, client_id: bytes) -> None:
    """Handling reconnection attempt request from a client"""
    username = struct.unpack(RECONNECTION_FORMAT, payload)[0].decode('utf-8').rstrip('\x00')  # remove padding bytes
    user = Users().get_user_by_username(username=username)

    if user is None or user.public_key is None or user.uuid != client_id:
        send_response(conn, ResponseCode.RECONNECTION_REJECTED, struct.pack(RECONNECTION_REJECTED_FORMAT, client_id))
        logger.warning(f"handle_reconnection: reconnection rejected for client id {client_id.hex()}: "
                       "user does not exist/public key is not stored/given username and client id do not match")

    else:  # User exists and public key was found
        # Create AES key and encrypt with RSA
        aes_key = generate_aes_key(AES_KEY_SIZE)
        user.aes_key = aes_key  # Store the aes key in the user object
        encrypted_aes_key = encrypt_aes_key(aes_key, user.public_key)

        send_response(conn, ResponseCode.RECONNECTION_PUBLIC_KEY_ACCEPTED_AES_EXCHANGE,
                      struct.pack(PUBLIC_KEY_ACCEPTED_AES_EXCHANGE_FORMAT, client_id) + encrypted_aes_key)
        logger.info(f"handle_reconnection: successfully reconnected for client id {client_id.hex()}")


def handle_file_transfer(conn: socket.socket, payload: bytes, client_id: bytes) -> None:
    """Handling file transfer request"""
    unpacked_metadata = struct.unpack(FILE_TRANSFER_METADATA_FORMAT, payload[:FILE_TRANSFER_METADATA_SIZE])
    file_size = int.from_bytes(unpacked_metadata[0], byteorder=ENDIAN_TYPE)
    orig_file_size = int.from_bytes(unpacked_metadata[1], byteorder=ENDIAN_TYPE)  # Before encryption
    packet_index = int.from_bytes(unpacked_metadata[2], byteorder=ENDIAN_TYPE)
    total_packets = int.from_bytes(unpacked_metadata[3], byteorder=ENDIAN_TYPE)
    file_name = unpacked_metadata[4].decode('utf-8').rstrip('\x00')
    msg_content = payload[FILE_TRANSFER_METADATA_SIZE:]

    if packet_index > total_packets or len(msg_content) > file_size:
        send_response(conn, ResponseCode.GENERAL_ERROR, b"")
        logger.warning(f"handle_file_transfer: given packet index {packet_index} "
                       f"is more than given total packets ({total_packets})")
        return

    user = Users().get_user_by_uuid(uuid=client_id)
    if user is None:
        send_response(conn, ResponseCode.GENERAL_ERROR, b"")
        logger.warning(f"handle_file_transfer: given client id {client_id.hex()} does not exist")
        return

    file = user.get_file(filename=file_name)
    if file is None:
        try:
            file = File(file_name=file_name, orig_total_size=orig_file_size, total_size=file_size,
                        packets_num=total_packets)
            user.add_file(file)
        except (FileDataError, UserDataError) as e:
            send_response(conn, ResponseCode.GENERAL_ERROR, b"")
            logger.warning(f"handle_file_transfer: failed to create File object for given file: {e}")
            return

    else:
        if (file.total_size != file_size or file.orig_total_size != orig_file_size or file.packets_num != total_packets
                or file.is_full()):
            send_response(conn, ResponseCode.GENERAL_ERROR, b"")
            logger.warning("handle_file_transfer: given file data doesn't match the data we have about the same file "
                           "or we already got all its data")
            return

    try:
        file.add_content(packet_id=packet_index, content=msg_content)
        logger.debug(f"handle_file_transfer: added content for file {file.file_name}")
    except FileDataError as e:
        send_response(conn, ResponseCode.GENERAL_ERROR, b"")
        logger.warning(f"handle_file_transfer: failed to add content for file: {e}")
        return

    if file.is_full() is False:
        return  # Don't return any response, wait for other packets to arrive

    if not user.aes_key:  # AES Key is not set
        send_response(conn, ResponseCode.GENERAL_ERROR, b"")
        logger.warning(f"handle_file_transfer: got all content for file {file.file_name},"
                       " but aes key is not set for user")
        return

    decrypted_data = decrypt_using_aes(data=file.curr_content, aes_key=user.aes_key)
    checksum = memcrc(decrypted_data)

    logger.info(f"handle_file_transfer: got all content for file {file.file_name},"
                " sending calculated checksum to client")
    send_response(conn, ResponseCode.VALID_FILE_WITH_CRC,
                  struct.pack(VALID_FILE_WITH_CRC_FORMAT, client_id,
                              int.to_bytes(file_size, length=CONTENT_SIZE_SIZE, byteorder=ENDIAN_TYPE),
                              file_name.encode("utf-8"),
                              int.to_bytes(checksum, length=CHECKSUM_SIZE, byteorder=ENDIAN_TYPE)),
                  )


def handle_crc_request_impl(conn: socket.socket, payload: bytes, client_id: bytes, request_code: int) -> None:
    """A common implementation for crc request from client"""
    file_name = struct.unpack(CRC_REQUEST_FORMAT, payload)[0].decode('utf-8').rstrip('\x00')  # remove padding bytes

    user = Users().get_user_by_uuid(uuid=client_id)
    if user is None:
        send_response(conn, ResponseCode.GENERAL_ERROR, b"")
        logger.warning(f"handle_crc_request: given client id {client_id.hex()} does not exist")
        return

    file = user.get_file(filename=file_name)
    if file is None:
        send_response(conn, ResponseCode.GENERAL_ERROR, b"")
        logger.warning(f"handle_crc_request: file object not found for client id {client_id.hex()}"
                       f" and file name {file_name}")
        return

    if request_code == RequestCode.VALID_CRC:
        logger.info(f"handle_valid_crc: client confirmed crc validity for client id {client_id.hex()}"
                    f" for file {file_name}")
        try:
            decrypted_data = decrypt_using_aes(data=file.curr_content, aes_key=user.aes_key)
            user_files_dir = os.path.join(USERS_FILES_DIR, user.uuid.hex())
            if not os.path.exists(user_files_dir):
                os.makedirs(user_files_dir)

            file_path = os.path.join(user_files_dir, os.path.basename(file_name))
            with open(file_path, "wb") as file_handler:
                file_handler.write(decrypted_data)

            UsersDB.add_file_for_user(file=file, file_path=file_path, user=user)

            # We are saving files that were verified by the user only, cause that's makes more sense
            send_response(conn, ResponseCode.MESSAGE_ACK, struct.pack(MESSAGE_ACK_FORMAT, user.uuid))
            logger.info(f"handle_valid_crc: saved file {file.file_name} to disk and acking back.")
        except Exception as e:
            logger.warning(f"handle_valid_crc: caught exception: {e}")
            send_response(conn, ResponseCode.GENERAL_ERROR, b"")
    elif request_code == RequestCode.INVALID_CRC_RETRY:
        if user.remove_file(file_name) is False:
            send_response(conn, ResponseCode.GENERAL_ERROR, b"")
            logger.warning(f"handle_invalid_crc_retry: failed to remove file {file_name} of client {client_id.hex()}")
        else:
            logger.info(f"handle_invalid_crc_retry: calculated crc is invalid for client id {client_id.hex()} "
                        f"for file {file_name}. Anticipating new file transfer requests.")
        # Not sending any response on purpose
    elif request_code == RequestCode.INVALID_CRC_DONE:
        if user.remove_file(file_name) is False:
            send_response(conn, ResponseCode.GENERAL_ERROR, b"")
            logger.warning(f"handle_invalid_crc_done: failed to remove file {file_name} of client {client_id.hex()}")
        else:
            send_response(conn, ResponseCode.MESSAGE_ACK, struct.pack(MESSAGE_ACK_FORMAT, user.uuid))
            logger.info(f"handle_invalid_crc_done: calculated crc is invalid for client id {client_id.hex()} "
                        f"for file {file_name}. Not anticipating new file transfer requests.")


def handle_valid_crc(conn: socket.socket, payload: bytes, client_id: bytes) -> None:
    """Handling valid crc request from client"""
    handle_crc_request_impl(conn, payload, client_id, RequestCode.VALID_CRC)


def handle_invalid_crc_retry(conn: socket.socket, payload: bytes, client_id: bytes) -> None:
    """Handling invalid crc retry request from client"""
    handle_crc_request_impl(conn, payload, client_id, RequestCode.INVALID_CRC_RETRY)


def handle_invalid_crc_done(conn: socket.socket, payload: bytes, client_id: bytes) -> None:
    """Handling invalid crc done request from client"""
    handle_crc_request_impl(conn, payload, client_id, RequestCode.INVALID_CRC_DONE)
