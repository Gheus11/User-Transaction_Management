from fastapi import FastAPI, HTTPException, Depends
from pydantic import EmailStr
from sqlalchemy import text
from sqlalchemy.orm import Session
from Backend_Classes import Item, User, Transaction, UserORM, TransactionORM, hash_password, verify_password
from typing import List
from datetime import datetime
from database import engine, get_db


api = FastAPI()

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
### ONLY ADMINS SHOULD BE ABLE TO SEE THIS!!!
@api.get("/users/", response_model=dict[str, List[User]])
def load_all_users(db: Session = Depends(get_db)):
    users = db.query(UserORM).all()
    return {"Users": [User.model_validate(user) for user in users]}


@api.get("/users/{user_id}/", response_model=dict[str, User])
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(UserORM).filter(UserORM.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=f'User with user id#{user_id} does not exist.')
    return {"User": User.model_validate(user)}


@api.post("/create_user/", response_model=dict[str, User])
def add_user(name: str, email: EmailStr, password: str, db: Session = Depends(get_db)):
    existing_user = db.query(UserORM).filter(UserORM.name == name).first()
    if existing_user:
        raise HTTPException(status_code=409, detail=f"User '{name}' already exists.")
    
    user = UserORM(name=name, email=email, created_at=datetime.now(), password=hash_password(password), is_admin=False)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"Added": User.model_validate(user)}


@api.put("/update_user/", response_model=dict[str, User])
def update_user(username: str, user_pw: str, db: Session = Depends(get_db),
                name: str | None = None,
                email: EmailStr | None = None,
                password: str | None = None,
                is_admin: bool | None = None):
    user = db.query(UserORM).filter(UserORM.name == username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f'User {name} does not exists.')
    
    is_admin_user = admin_user(username, user_pw)
    if not is_admin_user:
        if username != user.name or not verify_password(user_pw, user.password): 
            raise HTTPException(status_code=403, detail="User not allowed.")
        
    if all(detail is None for detail in (name, email, password, is_admin)):
        raise HTTPException(status_code=400, detail=f'No details to update for user {name}')
        
    user.name = name if name is not None else user.name
    user.email = email if email is not None else user.email
    user.password = hash_password(password) if password is not None else user.password
    user.is_admin = is_admin if is_admin is not None and is_admin_user else user.is_admin

    db.commit()
    db.refresh(user)
    return {"Updated": User.model_validate(user)}


@api.delete("/delete_user/", response_model=str)
def delete_user(username: str, user_pw: str, user_to_delete: str, db: Session = Depends(get_db)):
    requesting_user = db.query(UserORM).filter(UserORM.name == username).first()
    if not requesting_user:
        raise HTTPException(status_code=404, detail=f'User {username} does not exists.')
    
    target_user = db.query(UserORM).filter(UserORM.name == user_to_delete).first()
    if not target_user:
        raise HTTPException(status_code=404, detail=f'User {user_to_delete} does not exists.')
    
    is_admin_user = admin_user(username, user_pw)
    if not is_admin_user:
        if username != user_to_delete or not verify_password(user_pw, requesting_user.password): 
            raise HTTPException(status_code=403, detail="Password verification failed.")
        
    db.delete(target_user)
    db.commit()
    return f'Deleted user {user_to_delete}'


################################################ HELPER FUNCTIONS FOR USERS ################################################
def admin_user(name: str, password: str) -> bool:
    with engine.connect() as conn:
        result = conn.execute(text("""SELECT * FROM users WHERE name = :name"""),
                              {"name": name}).fetchone()
        if result and verify_password(password, result.hashed_pw):
            return result.is_admin
        return False
    

################################################ START OF HTTP REQUEST FUNCTIONS FOR TRANSACTIONS ################################################
@api.get('/transactions/', response_model=dict[str, List[Transaction]])
def load_transactions(username: str, password:str, db: Session = Depends(get_db)):
    user = db.query(UserORM).filter(UserORM.name == username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f'User {username} does not exists.')
    if not verify_password(password, user.password):
        raise HTTPException(status_code=403, detail="Password verification failed.")
    
    transactions = db.query(TransactionORM).filter(TransactionORM.user_id == user.id).all()
    if not transactions:
        raise HTTPException(status_code=404, detail=f'No transactions found for {username}.')
    
    return {"User transactions": [Transaction.model_validate(transaction) for transaction in transactions]}
    

@api.post('/add_transaction/', response_model=dict[str, Transaction])
def add_transaction(username: str, password: str, db: Session = Depends(get_db), 
                    money_earned: float | None = None, 
                    money_spent: float | None = None):
    if (money_earned is None) == (money_spent is None):
        raise HTTPException(status_code=400, detail=f'Either money_earned or money_spent must be given.')
    if money_earned is not None and money_earned <= 0:
        raise HTTPException(status_code=400, detail=f'money_earned must be positive.')
    if money_spent is not None and money_spent <= 0:
        raise HTTPException(status_code=400, detail=f'money_spent must be positive.')
    
    user = db.query(UserORM).filter(UserORM.name == username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f'User {username} does not exists.')
    if not verify_password(password, user.password):
        raise HTTPException(status_code=403, detail="Password verification failed.")
    
    money_earned = money_earned if money_earned else None
    date_time_earned = datetime.now() if money_earned is not None else None
    money_spent = money_spent if money_spent else None
    date_time_spent = datetime.now() if money_spent is not None else None
    
    transaction = TransactionORM(user_id=user.id, money_earned=money_earned, date_time_earned=date_time_earned, money_spent=money_spent, date_time_spent=date_time_spent)
    db.add(transaction)
    db.commit()
    db.refresh(transaction)
    return {"Added transaction": Transaction.model_validate(transaction)}


@api.put('/update_transaction/', response_model=dict[str, Transaction])
def update_transaction(username: str, password: str, transaction_id: int, db: Session = Depends(get_db),
                       money_earned: float | None = None,
                       money_spent: float | None = None):
    if (money_earned is None) == (money_spent is None):
        raise HTTPException(status_code=400, detail=f'Either money_earned or money_spent must be given.')
    if money_earned is not None and money_earned <=0:
        raise HTTPException(status_code=400, detail=f'money_earned must be positive.')
    if money_spent is not None and money_spent <=0:
        raise HTTPException(status_code=400, detail=f'money_spent must be positive.')

    user = db.query(UserORM).filter(UserORM.name == username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f'User {username} does not exist.')
    if not verify_password(password, user.password):
        raise HTTPException(status_code=403, detail=f'Password verification failed.')
    
    transaction = db.query(TransactionORM).filter(TransactionORM.id == transaction_id).first()
    if not transaction:
        raise HTTPException(status_code=404, detail=f'Transaction {transaction_id} does not exist.')
    if transaction.user_id != user.id:
        raise HTTPException(status_code=403, detail=f'User {username} not allowed to modify this entry.')
    
    if money_earned is not None:
        transaction.money_earned = money_earned
        transaction.date_time_earned = datetime.now()
        transaction.money_spent = None
        transaction.date_time_spent= None

    elif money_spent is not None:
        transaction.money_spent = money_spent
        transaction.date_time_spent= datetime.now()
        transaction.money_earned = None
        transaction.date_time_earned = None

    db.commit()
    db.refresh(transaction)
    return {"Updated transaction": Transaction.model_validate(transaction)}


@api.delete('/delete_transaction/', response_model=dict[str, Transaction])
def delete_transaction(username: str, password: str, transaction_id: int, db: Session = Depends(get_db)):
    user = db.query(UserORM).filter(UserORM.name == username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f'User {username} does not exist.')
    if not verify_password(password, user.password):
        raise HTTPException(status_code=403, detail=f'Password verification failed.')
    
    transaction = db.query(TransactionORM).filter(TransactionORM.id == transaction_id).first()
    if not transaction:
        raise HTTPException(status_code=404, detail=f'Transaction {transaction_id} does not exist.')
    if transaction.user_id != user.id:
        raise HTTPException(status_code=403, detail=f'User {username} not allowed to modify this entry.')
    
    db.delete(transaction)
    db.commit()
    return {"Deleted transaction": Transaction.model_validate(transaction)}
