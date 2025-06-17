from pydantic import BaseModel, EmailStr
from fastapi import HTTPException
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship
from enum import Enum
from datetime import datetime
from passlib.context import CryptContext
from jose import jwt, JWTError
from dotenv import load_dotenv
import os
from datetime import timedelta, timezone
from database import Base


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY not found in environment variables.")

PW_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

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


class TransactionORM(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    money_earned = Column(Float, nullable=True)
    date_time_earned = Column(DateTime, nullable=True)
    money_spent = Column(Float, nullable=True)
    date_time_spent = Column(DateTime, nullable=True)

    user = relationship("UserORM", back_populates="transactions")


def hash_password(password: str) -> str:
    return PW_CONTEXT.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return PW_CONTEXT.verify(password, password_hash) 


def generate_jwt_token(data: dict) -> str:
    to_encode = data.copy()
    expiry = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"sub": data.get("sub"), 
                      "exp": expiry})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")


def verify_jwt_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid JWT payload.")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired JWT.")