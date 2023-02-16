#!/usr/bin/env python3
""" Users model module
"""
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


# Creating a class model of Database
class User(Base):
    """SQLAlchemy map to a user table
    """
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, unique=True)
    email = Column(String(250), unique=True, nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)

    def __repr__(self):
        return f'<User {self.id} has email:{self.email}\
             and session ID:{self.session_id}>'
