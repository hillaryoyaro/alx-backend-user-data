#!/usr/bin/env python3
"""auth module
"""
import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from user import User
from typing import Union
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """returns a salted hash of the input password
        """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def _generate_uuid() -> str:
    """Returns a string representation of a new UUID
        """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()
        self.users = {}

    def register_user(self, email: str, password: str) -> User:
        """Register a new user in the authentication database.

        Args:
            email (str): The email of the user to register.
            password (str): The password of the user to register.

        Returns:
            User: The newly created User object.

        Raises:
            ValueError: If a user with the provided email already exists.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            pass
        hashed_password = _hash_password(password)
        user = self._db.add_user(email, hashed_password)

        return user

    def valid_login(self, email: str, password: str) -> bool:
        """Check if login credentials are valid or not
        """
        # user = None
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode("utf-8"),
                                  user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Create a new session ID for the user with the provided email.

    Args:
        email (str): The email of the user to create a new session ID for.

    Returns:
        str: The newly created session ID.

    Raises:
        ValueError: If the provided email does not correspond
         to a registered user.
    """
        try:
            user = self._db.find_user_by(email=email)
            new_session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=new_session_id)
            return new_session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """ Retrieves a user basd on session ID
        """
        user = None
        if session_id:
            try:
                user = self._db.find_user_by(session_id=session_id)
                return user
            except NoResultFound:
                return None
        return None

    def destroy_session(self, user_id: int) -> None:
        """Updates session ID to None
        """
        if user_id:
            self._db.update_user(user_id=user_id, session_id=None)
        return None
