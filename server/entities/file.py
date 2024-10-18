EMPTY_BYTES = b""


class FileDataError(Exception):
    pass


class File:
    """A class to represent a file transferred in our server-client communication"""

    def __init__(self, file_name: str, orig_total_size: int, total_size: int, packets_num: int) -> None:
        """A constructor for the File object, to store information about the transferred files."""
        if not isinstance(file_name, str):
            raise FileDataError("Given `file_name` for `File` creation must be of type str")
        if not isinstance(orig_total_size, int) or not isinstance(total_size, int) or not isinstance(packets_num, int):
            raise FileDataError("Given `total_size`, `packets_num` and `orig_total_size` for `File` creation must all "
                                "be of type int")
        if orig_total_size < 0 or total_size < 0 or packets_num < 0:
            raise FileDataError("Given `total_size`, `packets_num` and `orig_total_size` for `File` creation "
                                "must all be positive")

        self.__file_name = file_name
        self.__orig_total_size = orig_total_size  # Before encryption
        self.__total_size = total_size  # After encryption
        self.__packets_num = packets_num
        self.__stored_packets = 0
        self.__curr_content = [EMPTY_BYTES] * packets_num

    @property
    def file_name(self) -> str:
        """Property/getter function for the file_name member."""
        return self.__file_name

    @property
    def orig_total_size(self) -> int:
        """Property/getter function for the orig_total_size member."""
        return self.__orig_total_size

    @property
    def total_size(self) -> int:
        """Property/getter function for the total_size member."""
        return self.__total_size

    @property
    def packets_num(self) -> int:
        """Property/getter function for the public_key member."""
        return self.__packets_num

    @property
    def stored_packets(self) -> int:
        """Property/getter function for the stored_packets member."""
        return self.__stored_packets

    @property
    def curr_content(self) -> bytes:
        """Property/getter function for the curr_content member."""
        return EMPTY_BYTES.join(self.__curr_content)

    def is_full(self) -> bool:
        """Returns True if we already got all packets for the file, False if not"""
        return self.stored_packets >= self.packets_num

    def add_content(self, packet_id: int, content: bytes) -> None:
        """Add given content to current file's data"""
        if not isinstance(packet_id, int) or packet_id <= 0 or packet_id > self.packets_num:
            raise FileDataError("Given `packet_id` must be a positive int and not more than `packets_num`")

        if self.is_full():
            raise FileDataError("Content was requested to be added, but file got all expected packets")

        if len(self.__curr_content[packet_id - 1]) != 0:
            raise FileDataError(f"Content packet of id {packet_id} was already stored")

        if not isinstance(content, bytes) or len(content) <= 0:
            raise FileDataError("Given `content` must be a non-empty object of type `bytes`")

        self.__curr_content[packet_id - 1] = content
        self.__stored_packets += 1

        if self.is_full() and self.total_size != len(self.curr_content):
            raise FileDataError("Got all expected packets, but size doesn't match expected total size")
