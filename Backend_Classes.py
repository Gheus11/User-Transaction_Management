from pydantic import BaseModel, EmailStr
from enum import Enum
from datetime import datetime
from passlib.context import CryptContext


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


pw_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pw_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pw_context.verify(password, password_hash) 

