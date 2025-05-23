from fastapi import FastAPI, HTTPException, Form
from pydantic import EmailStr
from sqlalchemy import create_engine, text
from Backend_Classes import Item, Category, User, hash_password, verify_password
from typing import List
from dotenv import load_dotenv
import os
from datetime import datetime


load_dotenv()

DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")

api = FastAPI()
engine = create_engine(f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")


################################################ START OF HTTP REQUEST FUNCTIONS FOR ITEMS ################################################
@api.get("/")
@api.get("/items/")
def load_all_items() -> dict[str, List[Item]]:
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM items;"))

    items_db = []

    for row in result:
        item = Item(id = row.id,
            name = row.name,
            value = row.value,
            description = row.description,
            count = row.count,
            category = row.category)
        items_db.append(item)
    return {"items": items_db}


@api.get("/items/{item_id}/")
def get_item(item_id: int) -> dict[str, Item]:
    with engine.connect() as conn:
        result = conn.execute(text(f'SELECT * FROM items WHERE id = {item_id};')).fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail=f'Item with item id#{item_id} does not exist.')
    
    item = Item(id = result.id,
            name = result.name,
            value = result.value,
            description = result.description,
            count = result.count,
            category = result.category)
    return {"item": item}


@api.post("/items/")
def add_item(item: Item) -> dict[str, Item]:
    with engine.begin() as conn:
        result = conn.execute(text(f'SELECT * FROM items WHERE id = {item.id};')).fetchone()
        
        if result is not None:
            raise HTTPException(status_code=409, detail=f'Item with item id#{item.id} already exists.')
        else:
            conn.execute(text("""INSERT INTO items (id, name, value, description, count, category) OVERRIDING SYSTEM VALUE VALUES (:id, :name, :value, :description, :count, :category);"""),
                                  {"id": item.id,
                                   "name": item.name,
                                   "value": item.value,
                                   "description": item.description,
                                   "count": item.count,
                                   "category": item.category.value}) 
    return {"Added:": item} 


@api.put("/items/")
def update_item(
    item_id: int,
    name: str | None = None,
    value: float | None = None,
    description: str | None = None,
    count: int | None = None,
) -> dict[str, Item]:
    with engine.begin() as conn:
        result = conn.execute(text(f'SELECT * FROM items WHERE id = {item_id};')).fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail=f'Item with id {item_id} does not exists.')
        if all(detail is None for detail in (name, value, description, count)):
            raise HTTPException(status_code=404, detail=f'No details were updated for the item {item_id}')
            
        updated_name = name if name is not None else result.name
        updated_value = value if value is not None else result.value
        updated_description = description if description is not None else result.description
        updated_count = count if count is not None else result.count
        category = result.category

        conn.execute(text("""UPDATE items SET name = :updated_name, value = :updated_value, description = :updated_description, count = :updated_count WHERE id = :item_id;"""),
                   {"item_id": item_id,
                    "updated_name": updated_name,
                    "updated_value": updated_value,
                    "updated_description": updated_description,
                    "updated_count": updated_count})
        
        item = Item(id=item_id, name=updated_name, value=updated_value, description=updated_description, count=updated_count, category=category)
    return {"Updated:": item}


@api.delete("/items/")
def remove_item(item_id: int) -> dict[str, Item]:
    with engine.begin() as conn:
        result = conn.execute(text(f'SELECT * FROM items WHERE id = {item_id};')).fetchone() 

        if result is None:
            raise HTTPException(status_code=404, detail=f'Item with id {item_id} does not exists.')
        
        conn.execute(text("""DELETE FROM items WHERE id = :item_id;"""),
                     {"item_id": item_id})
        item = Item(id=item_id, name=result.name, value=result.value, description=result.description, count=result.count, category=result.category)
    return {"Removed:": item}


################################################ START OF HTTP REQUEST FUNCTIONS FOR USERS ################################################
@api.get("/users/")
def load_all_users() -> dict[str, List[User]]:
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM users;"))

    users_db = []
    
    for row in result:
        user = User(
            id = row.id,
            name = row.name,
            email = row.email,
            created_at = row.created_at,
            password = row.hashed_pw,
            is_admin = row.is_admin
        )
        users_db.append(user)
    return {"Users": users_db}


@api.get("/users/{user_id}/")
def get_user(user_id: int) -> dict[str, User]:
    with engine.connect() as conn:
        result = conn.execute(text(f'SELECT * FROM users WHERE id = {user_id}')).fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail=f'User with user id#{user_id} does not exist.')
    
    user = User(
            id = result.id,
            name = result.name,
            email = result.email,
            created_at = result.created_at,
            password = result.hashed_pw,
            is_admin = result.is_admin
        )
    return {"User": user}


@api.post("/users/")
def add_user(name: str, email: EmailStr, password: str) -> dict[str, User]:
    with engine.begin() as conn:
        result = conn.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name}).fetchone()
        if result is not None:
            raise HTTPException(status_code=409, detail=f"User '{name}' already exists.")
        else:
            user_insertion = conn.execute(text("""INSERT INTO users (name, email, created_at, hashed_pw, is_admin) VALUES (:name, :email, :created_at, :hashed_pw, :is_admin) RETURNING id, created_at, hashed_pw, is_admin;"""), 
                         {"name": name,
                          "email": email,
                          "created_at": datetime.now().isoformat(),
                          "hashed_pw":hash_password(password),
                          "is_admin": False
                         })
            
            row = user_insertion.fetchone()
            user_id = row.id
            user_created_at = row.created_at
            user_hashed_pw = row.hashed_pw
            user_is_admin = row.is_admin

    user = User(id=user_id, name=name, email=email, created_at=user_created_at, password=user_hashed_pw, is_admin=user_is_admin)
    return {"Added": user}


@api.put("/users/")
def update_user(username: str, user_pw: str,
    user_id: int,
    name: str | None = None,
    email: EmailStr | None = None,
    password: str | None = None,
    is_admin: bool | None = None
) -> dict[str, User]:
    with engine.begin() as conn:
        result = conn.execute(text(f'SELECT * FROM users WHERE id = {user_id};')).fetchone()

        if result is None:
            raise HTTPException(status_code=404, detail=f'User with id {user_id} does not exists.')

        if not admin_user(username, user_pw):
            if username != result.name or not verify_password(user_pw, result.hashed_pw): 
                raise HTTPException(status_code=403, detail="User not allowed.")
        
        if all(detail is None for detail in (name, email, password, is_admin)):
            raise HTTPException(status_code=404, detail=f'No details were updated for the user {user_id}')
        
        updated_name = name if name is not None else result.name
        updated_password = hash_password(password) if password is not None else result.hashed_pw
        updated_is_admin = is_admin if is_admin is not None else result.is_admin
        created_at = result.created_at
        updated_email = email if email is not None else result.email

        conn.execute(text("""UPDATE users SET name = :updated_name, email = :updated_email, hashed_pw = :updated_password, is_admin = :updated_is_admin WHERE id = :user_id;"""),
                    {"user_id": user_id,
                    "updated_name": updated_name,
                    "updated_email": updated_email,
                    "updated_password": updated_password,
                    "updated_is_admin": updated_is_admin})
    
    user = User(id=user_id, name=updated_name, email=updated_email, created_at=created_at, password=updated_password, is_admin=updated_is_admin)
    return {"Updated": user}


@api.delete("/users/")
def delete_user(username: str, user_pw: str, user_id: int) -> dict[str, User]:
    with engine.begin() as conn:
        result = conn.execute(text(f'SELECT * FROM users WHERE id = {user_id};')).fetchone()
        if result is None:
            raise HTTPException(status_code=404, detail=f'User with id {user_id} does not exists.')
        
        if not admin_user(username, user_pw):
            if username != result.name or not verify_password(user_pw, result.hashed_pw): 
                raise HTTPException(status_code=403, detail="User not allowed.")
        
        conn.execute(text("""DELETE FROM users WHERE id = :user_id;"""),
                     {"user_id": user_id})
        user = User(id=user_id, name=result.name, email=result.email, created_at=result.created_at, password=result.hashed_pw, is_admin=result.is_admin)
    return {"Deleted": user}


################################################ HELPER FUNCTIONS FOR USERS ################################################
def admin_user(name: str, password: str) -> bool:
    with engine.connect() as conn:
        result = conn.execute(text("""SELECT * FROM users WHERE name = :name"""),
                              {"name": name}).fetchone()
        if result and verify_password(password, result.hashed_pw):
            return result.is_admin
        return False