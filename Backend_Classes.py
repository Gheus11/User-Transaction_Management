from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey, Enum as AEnum
from enum import Enum
from sqlalchemy.orm import relationship
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


class UserORM(Base):
    __tablename__ = "users" 

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, index=True)
    created_at = Column(DateTime)
    password = Column("hashed_pw", String)
    is_admin = Column(Boolean)

    transactions = relationship("TransactionORM", back_populates="user", cascade="all, delete-orphan")
    jwt_token = relationship("JWT_TokenORM", back_populates="user", cascade="all, delete-orphan")

class Category(str, Enum):
    groceries = "groceries"
    clothing = "clothing"
    repairs = "repairs"
    subscription = "subscription"
    rent = "rent"
    restaurant = "restaurant"
    entertainment = "entertainment"
    gift = "gift"


class TransactionORM(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    money_earned = Column(Float, nullable=True)
    date_time_earned = Column(DateTime, nullable=True)
    money_spent = Column(Float, nullable=True)
    date_time_spent = Column(DateTime, nullable=True)
    purpose_details = Column(String, nullable=False)
    category = Column(AEnum(Category), nullable=False)

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

