import socket
import struct

from .constants import (REQUEST_HEADER_FORMAT, REQUEST_HEADER_SIZE, RequestCode, MAX_BYTES_READ, ENDIAN_TYPE,
                       CLIENT_VERSION, ResponseCode, MESSAGE_ACK_FORMAT)
from .requests_handlers import handle_registration, handle_key_exchange, handle_reconnection, handle_file_transfer, \
    handle_valid_crc, handle_invalid_crc_retry, handle_invalid_crc_done, send_response
from common.utils import logger
from entities.users import Users
from entities.users_db import UsersDB


def process_request(conn: socket.socket, data: bytes) -> None:
    """Process incoming request from a client according to the given request code"""
    header = struct.unpack(REQUEST_HEADER_FORMAT, data[:REQUEST_HEADER_SIZE])
    client_id, version, request_code, payload_size = header
    version = int.from_bytes(version, byteorder=ENDIAN_TYPE)
    request_code = int.from_bytes(request_code, byteorder=ENDIAN_TYPE)
    payload_size = int.from_bytes(payload_size, byteorder=ENDIAN_TYPE)

    payload = data[REQUEST_HEADER_SIZE:REQUEST_HEADER_SIZE + payload_size]

    if version != CLIENT_VERSION:  # Verify received version
        send_response(conn, ResponseCode.GENERAL_ERROR, struct.pack(MESSAGE_ACK_FORMAT, client_id))

    # Update last seen for client, if relevant
    user = Users().get_user_by_uuid(client_id)
    if user is not None:
        logger.info(f"Updating last seen for client id {client_id.hex()}")
        UsersDB.update_user_last_seen(user)

    if request_code == RequestCode.REGISTRATION:
        handle_registration(conn, payload, client_id)
    elif request_code == RequestCode.PUBLIC_KEY_EXCHANGE:
        handle_key_exchange(conn, payload, client_id)
    elif request_code == RequestCode.RECONNECTION_ATTEMPT:
        handle_reconnection(conn, payload, client_id)
    elif request_code == RequestCode.FILE_TRANSFER:
        handle_file_transfer(conn, payload, client_id)
    elif request_code == RequestCode.VALID_CRC:
        handle_valid_crc(conn, payload, client_id)
    elif request_code == RequestCode.INVALID_CRC_RETRY:
        handle_invalid_crc_retry(conn, payload, client_id)
    elif request_code == RequestCode.INVALID_CRC_DONE:
        handle_invalid_crc_done(conn, payload, client_id)


def read(conn: socket.socket) -> None:
    """Reading a request from the client and processing the request."""
    while True:
        try:
            data = conn.recv(MAX_BYTES_READ)
            if data:
                process_request(conn, data)
        except socket.timeout:
            logger.debug("Socket read timed out.")
            break
        except Exception as e:
            logger.debug(f"Socket read error or socket was closed by client: {e}")
            break
    conn.close()
