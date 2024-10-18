import logging
import socket
import threading

from common.utils import logger
from communication.communication import read
from entities.users_db import UsersDB

# Constants:
STORAGE_FILE_PATH = "storage"
PORT_INFO_FILE_PATH = "port.info"
PORT_MIN_VAL = 1
PORT_MAX_VAL = 65535
DEFAULT_PORT = 1256
HOST = "127.0.0.1"  # localhost


def get_server_port() -> int:
    """
    Read server port from {PORT_INFO_PATH} and return it.
    If the file doesn't exist, or it's an invalid port - return {DEFAULT_PORT}.
    """
    try:
        with open(PORT_INFO_FILE_PATH, "r") as port_info_file:
            file_content = port_info_file.read().strip()
        port = int(file_content)

        assert PORT_MIN_VAL <= port <= PORT_MAX_VAL, \
            f"Read port {port} is not in the valid range ({PORT_MIN_VAL} to {PORT_MAX_VAL})"  # Check validity
        return port
    except Exception as e:
        logging.warning(f"There was an error reading port from {PORT_INFO_FILE_PATH}: {e}. "
                        f"Defaulting to {DEFAULT_PORT}.")
        return DEFAULT_PORT


def server_start(port: int) -> None:
    """The main server start function."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Bind the socket to the host and port
        server_socket.bind((HOST, port))

        server_socket.listen(5)  # Maximum number of queued connections
        logger.info(f"listening on {HOST}:{port}")

        while True:
            client_socket, client_address = server_socket.accept()
            logger.info(f"accepted connection from {client_address}")
            client_thread = threading.Thread(target=read, args=(client_socket,))
            client_thread.start()


def main() -> None:
    """Main server's function."""
    UsersDB.init_db()
    port = get_server_port()
    server_start(port)


if __name__ == "__main__":
    main()
