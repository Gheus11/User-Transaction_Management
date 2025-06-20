from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship
from enum import Enum
from datetime import datetime
from passlib.context import CryptContext
from dotenv import load_dotenv
import os
from database import Base


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY not found in environment variables.")

HASH_ALG = "HS256"
PW_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class Category(Enum):
    FOOD = 'Food'
    BEVERAGE = 'Beverage'
    POTION = 'Potion'


class Item(BaseModel):
    id: int
    name: str
    value: float
    description: str
    count: int
    category: Category


class User(BaseModel):
    id: int
    name: str
    email: EmailStr
    created_at: datetime
    password: str
    is_admin: bool

    class Config:
        from_attributes = True


class Transaction(BaseModel):
    id: int
    user_id: int
    money_earned: float | None
    date_time_earned: datetime | None
    money_spent: float | None
    date_time_spent: datetime | None

    class Config:
        from_attributes = True


class UserORM(Base):
    __tablename__ = "users" 

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, index=True)
    created_at = Column(DateTime)
    password = Column("hashed_pw", String)
    is_admin = Column(Boolean)

    transactions = relationship("TransactionORM", back_populates="user")
    jwt_token = relationship("JWT_TokenORM", back_populates="user")


class TransactionORM(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    money_earned = Column(Float, nullable=True)
    date_time_earned = Column(DateTime, nullable=True)
    money_spent = Column(Float, nullable=True)
    date_time_spent = Column(DateTime, nullable=True)

    user = relationship("UserORM", back_populates="transactions")


class JWT_TokenORM(Base):
    __tablename__ = "jwt_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token = Column(String, index=True)
    date_time_created = Column(DateTime)
    expiry = Column(DateTime)
    is_blacklisted = Column(Boolean, default=False)

    user = relationship("UserORM", back_populates="jwt_token")


def hash_password(password: str) -> str:
    return PW_CONTEXT.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return PW_CONTEXT.verify(password, password_hash) 

