from typing import Optional

from common.utils import generate_uuid
from .user import User, UserDataError
from .users_db import UsersDB


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Users(metaclass=Singleton):
    """A class to represent the interface of users for the server."""
    def __init__(self) -> None:
        """Init function for the Users function"""
        self.__users_dict = UsersDB.get_users_dict()

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Given a username, returns a User object representing the User. If the user does not exist - returns None."""
        for _, user in self.__users_dict.items():
            if user.username == username:
                return user
        return None

    def get_user_by_uuid(self, uuid: bytes) -> Optional[User]:
        """Given uuid, returns a User object representing the User. If the user does not exist - returns None."""
        return self.__users_dict.get(uuid)

    def register_user(self, username: str) -> bytes:
        """Given a username for a User, verifies the user doesn't already exist in the Users data,
           and if it's not - add it, and return a generated uuid."""
        if self.get_user_by_username(username) is not None:
            raise UserDataError(f"User with username '{username}' already exists. Please choose another username.")

        user_uuid = generate_uuid()
        user = User(username=username, uuid=user_uuid)
        self.__users_dict[user_uuid] = user

        return user_uuid
