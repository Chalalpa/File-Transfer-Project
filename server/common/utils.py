import uuid
import logging
import struct

# Configuring logging
logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])
logger = logging.getLogger("Server")


def generate_uuid() -> bytes:
    """Randomly generates a (16 bytes) UUID and returns it."""
    return uuid.uuid4().bytes


def int_to_little_endian_bytes(value) -> bytes:
    return struct.pack('<I', value)
