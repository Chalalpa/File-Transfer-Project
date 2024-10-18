from typing import Optional, Dict

from .file import File

UUID_BYTE_SIZE = 16


class UserDataError(Exception):
    """An exception class to represent errors related to user registration"""
    pass


class User:
    """A class to represent a server's user."""
    def __init__(self, username: str, uuid: bytes, public_key: Optional[bytes] = None, aes_key: Optional[bytes] = None
                 ) -> None:
        """A constructor for the User object, to store information about the server's users."""
        if not isinstance(username, str):
            raise UserDataError("Given `username` for `User` creation must be of type str")
        if not isinstance(uuid, bytes) or len(uuid) != UUID_BYTE_SIZE:
            raise UserDataError("Given `uuid` for `User` creation must be of type bytes,"
                                f" with length of {UUID_BYTE_SIZE}")
        if public_key is not None and (not isinstance(public_key, bytes) or len(public_key) == 0):
            raise UserDataError("Given `public_key` for `User` creation must be of type bytes and not empty")

        if aes_key is not None and (not isinstance(aes_key, bytes) or len(aes_key) == 0):
            raise UserDataError("Given `aes_key` for `User` creation must be of type bytes and not empty")

        self.__username = username
        self.__uuid = uuid
        self.__public_key = public_key
        self.__aes_key = aes_key
        self.__files: Dict[str, File] = {}

    @property
    def username(self) -> str:
        """Property/getter function for the username member."""
        return self.__username

    @property
    def uuid(self) -> bytes:
        """Property/getter function for the uuid member."""
        return self.__uuid

    @property
    def public_key(self) -> bytes:
        """Property/getter function for the public_key member."""
        return self.__public_key

    @public_key.setter
    def public_key(self, public_key: bytes) -> None:
        """Setter function for the public_key member"""
        if not isinstance(public_key, bytes) or len(public_key) == 0:
            raise UserDataError("Given `public_key` must be of type bytes and not empty")
        self.__public_key = public_key

    @property
    def aes_key(self) -> bytes:
        """Property/getter function for the aes_key member."""
        return self.__aes_key

    @aes_key.setter
    def aes_key(self, aes_key: bytes) -> None:
        """Setter function for the aes_key member"""
        if not isinstance(aes_key, bytes) or len(aes_key) == 0:
            raise UserDataError("Given `aes_key` must be of type bytes and not empty")
        self.__aes_key = aes_key

    def get_file(self, filename: str) -> Optional[File]:
        """Given a filename, returns a File object if the user has one with that name. Otherwise - returns None."""
        return self.__files.get(filename)

    def add_file(self, file: File) -> None:
        """Store a File object in the files list of the user"""
        if not isinstance(file, File):
            raise UserDataError("Given `file` must be of type `File`")

        if file.file_name in self.__files.keys():
            raise UserDataError(f"File with name {file.file_name} already exists for user {self.username}")

        self.__files[file.file_name] = file

    def remove_file(self, file_name: str) -> bool:
        """Removes a given file (by name) from user's files dict"""
        if not isinstance(file_name, str) or file_name not in self.__files.keys():
            return False

        del self.__files[file_name]
        return True
