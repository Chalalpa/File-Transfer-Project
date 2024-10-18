import sqlite3
from sqlite3 import Connection
from datetime import datetime
from typing import List, Dict

from entities.file import File
from entities.user import User

# DB Details
DATABASE_FILE_NAME = "db.defensive"
CLIENTS_TABLE_NAME = "clients"
FILES_TABLE_NAME = "files"

# Users Table
ID_COLUMN = "ID"
NAME_COLUMN = "Name"
PUBLIC_KEY_COLUMN = "PublicKey"
LAST_SEEN_COLUMN = "LastSeen"
AES_KEY_COLUMN = "AESKey"

# Files Table
FILE_NAME_COLUMN = "FileName"
PATH_NAME_COLUMN = "PathName"
VERIFIED_COLUMN = "Verified"

ID_COLUMN_LENGTH = 16
NAME_COLUMN_LENGTH = PATH_NAME_COLUMN_LENGTH = FILE_NAME_COLUMN_LENGTH = 255
PUBLIC_KEY_COLUMN_LENGTH = 20
AES_KEY_COLUMN_LENGTH = 32


class UsersDBError(Exception):
    """An exception class to represent errors related to the Users DB"""
    pass


class UsersDB:
    @staticmethod
    def __get_database_connection() -> Connection:
        """Create a new database connection."""
        return sqlite3.connect(DATABASE_FILE_NAME)

    @staticmethod
    def init_db() -> None:
        """Create the required tables if they do not exist already"""
        with UsersDB.__get_database_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {CLIENTS_TABLE_NAME} (
                {ID_COLUMN} BLOB({ID_COLUMN_LENGTH}) PRIMARY KEY,
                {NAME_COLUMN} TEXT NOT NULL CHECK(length({NAME_COLUMN}) <= {NAME_COLUMN_LENGTH}),
                {PUBLIC_KEY_COLUMN} BLOB({PUBLIC_KEY_COLUMN_LENGTH}) NOT NULL,
                {LAST_SEEN_COLUMN} DATETIME NOT NULL,
                {AES_KEY_COLUMN} BLOB({AES_KEY_COLUMN_LENGTH}) NOT NULL
            );
            ''')

            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {FILES_TABLE_NAME} (
                {ID_COLUMN} BLOB({ID_COLUMN_LENGTH}) NOT NULL,
                {FILE_NAME_COLUMN} TEXT NOT NULL CHECK(length({FILE_NAME_COLUMN}) <= {FILE_NAME_COLUMN_LENGTH}),
                {PATH_NAME_COLUMN} TEXT NOT NULL CHECK(length({PATH_NAME_COLUMN}) <= {PATH_NAME_COLUMN_LENGTH}),
                {VERIFIED_COLUMN} BOOLEAN NOT NULL,
                PRIMARY KEY ({ID_COLUMN}, {FILE_NAME_COLUMN})
            );
            ''')

            conn.commit()

    @staticmethod
    def get_files_of_user(user: User) -> List[File]:
        """Returns a cursor describing the files of a registered client by its name"""
        try:
            with UsersDB.__get_database_connection() as conn:
                cursor = conn.cursor()

                cursor.execute(f'SELECT {FILE_NAME_COLUMN} FROM {FILES_TABLE_NAME} WHERE {ID_COLUMN} = ?;',
                               (user.uuid,))
                files = cursor.fetchall()

                user_files = []
                for file in files:
                    # We are inserting 0 to some of the file object's details,
                    # because we don't know, and we don't need to know these details - it's already saved, and
                    # we should not receive anymore packets of it.
                    file_obj = File(file_name=file[0], orig_total_size=0, total_size=0, packets_num=0)
                    user_files.append(file_obj)

                return user_files
        except Exception as e:
            raise UsersDBError(e)

    @staticmethod
    def get_users_dict() -> Dict[bytes, User]:
        """Initializes the users dict from the DB, and returns it"""
        users_dict = {}

        try:
            with UsersDB.__get_database_connection() as conn:
                cursor = conn.cursor()

                cursor.execute(f'SELECT {ID_COLUMN},{NAME_COLUMN},{PUBLIC_KEY_COLUMN},{AES_KEY_COLUMN} '
                               f'FROM {CLIENTS_TABLE_NAME};')
                users = cursor.fetchall()

                for user in users:
                    user_obj = User(uuid=user[0], username=user[1], public_key=user[2], aes_key=user[3])
                    for file in UsersDB.get_files_of_user(user_obj):
                        user_obj.add_file(file)
                    users_dict[user_obj.uuid] = user_obj
        except Exception as e:
            raise UsersDBError(e)

        return users_dict

    @staticmethod
    def add_user(user: User) -> None:
        """Adds a given user to the DB"""
        if not isinstance(user, User):
            raise UsersDBError("add_user function must receive a valid User object")

        try:
            with UsersDB.__get_database_connection() as conn:
                cursor = conn.cursor()

                insert_query = f"""
                INSERT INTO {CLIENTS_TABLE_NAME} ({ID_COLUMN}, {NAME_COLUMN}, {PUBLIC_KEY_COLUMN},
                            {LAST_SEEN_COLUMN}, {AES_KEY_COLUMN})
                VALUES (?, ?, ?, ?, ?)
                """

                curr_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute(insert_query,
                               (user.uuid, user.username, user.public_key, curr_time, user.aes_key))
                conn.commit()
        except Exception as e:
            raise UsersDBError(e)

    @staticmethod
    def update_user_last_seen(user: User) -> None:
        """Updates a given user's last seen to current time"""
        if not isinstance(user, User):
            raise UsersDBError("update_user_last_seen function must receive a valid User object")

        try:
            with UsersDB.__get_database_connection() as conn:
                cursor = conn.cursor()

                update_query = f"""
                UPDATE {CLIENTS_TABLE_NAME}
                SET {LAST_SEEN_COLUMN} = ?
                WHERE {ID_COLUMN} = ?
                """

                curr_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute(update_query, (curr_time, user.uuid))
                conn.commit()
        except Exception as e:
            raise UsersDBError(e)

    @staticmethod
    def add_file_for_user(file: File, user: User, file_path: str) -> None:
        """Adds a given file to the files table"""
        if not isinstance(user, User):
            raise UsersDBError("update_user_last_seen function must receive a valid User object")

        if not isinstance(file, File):
            raise UsersDBError("update_user_last_seen function must receive a valid File object")

        if not isinstance(file_path, str):
            raise UsersDBError("update_user_last_seen function must receive a file_path of type str")

        try:
            with UsersDB.__get_database_connection() as conn:
                cursor = conn.cursor()

                insert_query = f"""
                INSERT INTO {FILES_TABLE_NAME} ({ID_COLUMN}, {FILE_NAME_COLUMN}, {PATH_NAME_COLUMN}, {VERIFIED_COLUMN})
                VALUES (?, ?, ?, ?)
                """

                # Our assumption, is that we are going to store on the disk only files that were verified by the client
                # That's why Verified=True is hardcoded here.
                cursor.execute(insert_query, (user.uuid, file.file_name, file_path, True))
                conn.commit()

        except Exception as e:
            raise UsersDBError(e)
