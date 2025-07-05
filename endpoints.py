from fastapi import FastAPI, Request, Form, Cookie, HTTPException, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import EmailStr
from sqlalchemy import text
from sqlalchemy.orm import Session
from Backend_Classes import User, Transaction, UserORM, TransactionORM, JWT_TokenORM, hash_password, verify_password, SECRET_KEY, HASH_ALG
from typing import List
from datetime import datetime, timezone, timedelta
from database import engine, get_db
from jose import jwt, JWTError


api = FastAPI()
templates = Jinja2Templates(directory="Frontend")

################################################ LOGIN + JWT + LOGOUT ################################################
@api.get("/")
def main_page(request: Request):
    message_create = request.cookies.get("message_create")
    message_update = request.cookies.get("message_update")
    if message_create:
        response = templates.TemplateResponse("main_page.html", {"request": request, "message_create": message_create}) 
    elif message_update:
        response = templates.TemplateResponse("main_page.html", {"request": request, "message_update": message_update})
    else:
        response = templates.TemplateResponse("main_page.html", {"request": request})

    if message_create:
        response.delete_cookie("message_create")
    if message_update:
        response.delete_cookie("message_update")
    return response


@api.post("/login/", response_class=HTMLResponse)
def log_in(request: Request, username: str = Form(), password: str = Form(), db: Session = Depends(get_db)):
    user = db.query(UserORM).filter(UserORM.name == username).first()
    if not user or not verify_password(password, user.password):
        return templates.TemplateResponse("main_page.html", {"request": request, "message": "Incorrect username or password."})
        
    jwt_token = generate_jwt_token(username)
    token_payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[HASH_ALG])
    token_expiry = datetime.fromtimestamp(token_payload["exp"], tz=timezone.utc)
    jwt_token_orm = JWT_TokenORM(user_id=user.id ,token=jwt_token, date_time_created=datetime.now(timezone.utc), expiry=token_expiry)

    db.add(jwt_token_orm)
    db.commit()

    jwt_id = str(jwt_token_orm.id)

    if user.is_admin:
        response = RedirectResponse(url="/hub-admin/", status_code=303)
    else:
        response = RedirectResponse(url="/hub/", status_code=303)

    response.set_cookie(key="session_id", value=jwt_id, httponly=True, secure=False, samesite="lax", max_age=900)
    response.set_cookie(key="username", value=username, httponly=False, max_age=900)
    return response


def generate_jwt_token(username: str) -> str:
    expiry = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode = {"sub": username, "exp": expiry}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=HASH_ALG)


def jwt_required(request: Request, db: Session = Depends(get_db)) -> UserORM:
    token_id = request.cookies.get("session_id")
    if not token_id:
        raise HTTPException(status_code=401, detail="JWT missing or expired.")
    
    try:
        token = db.query(JWT_TokenORM).filter(JWT_TokenORM.id == token_id).first()
    except ValueError:
        raise HTTPException(status_code=404, detail="Invalid session ID.")
    
    if not token or token.is_blacklisted:
        raise HTTPException(status_code=404, detail="Token doesn't exist or expired.")

    try:
        jwt.decode(token.token, SECRET_KEY, algorithms=[HASH_ALG])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token.")    
    
    user = db.query(UserORM).filter(UserORM.id == token.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Associated user doesn't exist.")
    return user



def verify_jwt_token(token: str, db: Session = Depends(get_db)) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[HASH_ALG])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid JWT payload.")     
        
        requested_token = db.query(JWT_TokenORM).filter_by(token=token).first()
        if not requested_token:
            raise HTTPException(status_code=401, detail="Token does not exist.")
        if requested_token.is_blacklisted:
            raise HTTPException(status_code=401, detail="This JWT token has been blacklisted (Token Expired).")

        if datetime.fromtimestamp(payload["exp"], tz=timezone.utc) < datetime.now(timezone.utc):
              requested_token.is_blacklisted = True
              db.commit()
              raise HTTPException(status_code=401, detail="Expired JWT token.")
           
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired JWT.")
    

def get_current_user(request: Request, db: Session = Depends(get_db)) -> UserORM:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=404, detail=f"Token doesn't exist or expired.")
    
    username = verify_jwt_token(token, db)
    user = db.query(UserORM).filter(UserORM.name == username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f'User {username} does not exist.')
    return user



@api.get("/hub/", response_class=HTMLResponse)
def main_hub(request: Request, user: UserORM = Depends(jwt_required)):
    username = user.name
    message = request.cookies.get("message")
    expired_auth = request.cookies.get("expired_auth")
    response = templates.TemplateResponse("main_hub.html", {"request": request, "username": username, "user": user, "message": message if message else expired_auth})
    response.delete_cookie("message")
    return response


@api.get("/hub-admin/", response_class=HTMLResponse)
def main_hub(request: Request, user: UserORM = Depends(jwt_required)):
    if not user.is_admin:
        response = RedirectResponse("/hub/", status_code=303)
        response.set_cookie(key="message", value="User not allowed.", max_age=5)
        return response
    expired_auth = request.cookies.get("expired_auth")
    username = request.cookies.get("username")
    response = templates.TemplateResponse("main_hub-admin.html", {"request": request, "username": username, "message": expired_auth})
    return response


@api.get("/logout/", response_class=HTMLResponse)
def logout(request: Request, user: UserORM = Depends(jwt_required), db: Session = Depends(get_db)):
    session_id = request.cookies.get("session_id")
    if not session_id:
        return templates.TemplateResponse("main_page.html", {"request": request, "message": "Not logged in"})
    
    user_token = db.query(JWT_TokenORM).filter_by(id=session_id).first()
    if (not user_token) or (user_token.is_blacklisted):
        return templates.TemplateResponse("main_page.html", {"request": request, "message": "Not logged in or session expired."})
    
    user_token.is_blacklisted = True
    db.commit()

    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("session_id")
    response.delete_cookie("username")
    return response


@api.exception_handler(StarletteHTTPException)
def status_code_handler(request: Request, exec: StarletteHTTPException):
    if exec.status_code == 401:
        return RedirectResponse("/", status_code=303)
    if exec.status_code == 404:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)
    return PlainTextResponse(str(exec.detail), status_code=exec.status_code)


################################################ START OF HTTP REQUEST FUNCTIONS FOR USERS ################################################
@api.get("/users/", response_class=HTMLResponse)
def load_all_users(request: Request, user: UserORM = Depends(jwt_required), db: Session = Depends(get_db)):
    if not user.is_admin:
        response = RedirectResponse("/hub/", status_code=303)
        response.set_cookie(key="message", value="User not allowed.", max_age=5)
        return response
    
    users = db.query(UserORM).all()
    response = templates.TemplateResponse("users.html", {"request": request, "users": users})
    response.headers["Cache-Control"] = "no-store"
    return response


@api.get("/create_user/", response_class=HTMLResponse)
def sign_up_form(request: Request):
    response = templates.TemplateResponse("user_creation.html", {"request": request})
    return response


@api.post("/create_user/", response_class=HTMLResponse)
def add_user(request: Request, name: str = Form(), email: EmailStr = Form(), password: str = Form(), db: Session = Depends(get_db)):
    existing_user = db.query(UserORM).filter(UserORM.name == name).first()
    if existing_user:
        return templates.TemplateResponse("user_creation.html", {"request": request, "message": f"User '{name}' already exists."})
        
    user = UserORM(name=name, email=email, created_at=datetime.now(timezone.utc), password=hash_password(password), is_admin=False)
    db.add(user)
    db.commit()
    db.refresh(user)

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(key="message_create", value="Account successfully created!", max_age=5)
    return response


@api.get("/update_user/", response_class=HTMLResponse)
def update_form(request: Request, user: UserORM = Depends(jwt_required)):
    can_edit = request.cookies.get("can_edit_or_delete")
    if can_edit != "1":
        if user.is_admin:
            response = RedirectResponse("/hub-admin/", status_code=303)
        else:
            response = RedirectResponse("/hub/", status_code=303)
        return response

    response = templates.TemplateResponse("user_update.html", {"request": request})
    response.headers["Cache-Control"] = "no-store"
    return response


@api.post("/update_user/", response_class=HTMLResponse)
def update_user(request: Request, 
                user: UserORM = Depends(jwt_required),
                db: Session = Depends(get_db),
                method_override: str = Form(),
                name: str | None = Form(None),
                email: str | None = Form(None),
                password: str | None = Form(None)):
    if method_override.lower() != "put":
        raise HTTPException(status_code=405, detail="Method not allowed.")
    
    username = request.cookies.get("username")
    user = db.query(UserORM).filter(UserORM.name == username).first()
    if not user:
        return templates.TemplateResponse("user_update.html", {"request": request, "message": f"User {name} does not exists."})
    
    can_edit = request.cookies.get("can_edit_or_delete")
    if can_edit != "1":
        if user.is_admin:
            response = RedirectResponse("/hub-admin/", status_code=303)
        else:
            response = RedirectResponse("/hub/", status_code=303)
        response.set_cookie(key="expired_auth", value="Edit session expired, please try again.", max_age=5)
        return response
        
    if all(not detail for detail in (name, email, password)):
        return templates.TemplateResponse("user_update.html", {"request": request, "message": f"Please enter details to update."})
    
    if name and name != user.name:
        existing_name = db.query(UserORM).filter(UserORM.name == name).first()
        if existing_name:
            return templates.TemplateResponse("user_update.html", {"request": request, "message": f"Username {name} already exists."})
        user.name = name
        
    user.email = email if email else user.email
        
    if password and password != user.password:
        if len(password.strip()) < 3:
            return templates.TemplateResponse("user_update.html", {"request": request, "message": f"Password must contain 3 or more characters"})
        user.password = hash_password(password)

    db.commit()
    db.refresh(user)

    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("session_id")
    response.delete_cookie("username")
    response.delete_cookie("can_edit_or_delete")
    response.set_cookie(key="message_update", value="Account info updated successfully! Please login again.", max_age=5)
    return response


@api.get("/delete_user/", response_class=HTMLResponse)
def delete_form(request: Request, user: UserORM = Depends(jwt_required)):
    can_delete = request.cookies.get("can_edit_or_delete")
    if can_delete != "1":
        if user.is_admin:
            response = RedirectResponse("/hub-admin/", status_code=303)
        else:
            response = RedirectResponse("/hub/", status_code=303)
        return response

    response = templates.TemplateResponse("user_delete.html", {"request": request})
    response.headers["Cache-Control"] = "no-store"
    return response


@api.post("/delete_user/", response_class=HTMLResponse)
def delete_user(request: Request, user: UserORM = Depends(jwt_required), method_override: str = Form(), db: Session = Depends(get_db)):
    if method_override != "delete":
        raise HTTPException(status_code=405, detail="Method not allowed.")
    
    can_delete = request.cookies.get("can_edit_or_delete")
    if can_delete != "1":
        if user.is_admin:
            response = RedirectResponse("/hub-admin/", status_code=303)
        else:
            response = RedirectResponse("/hub/", status_code=303)
        response.set_cookie(key="expired_auth", value="Delete session expired, please try again.", max_age=5)
        return response

    username = request.cookies.get("username")
    user = db.query(UserORM).filter(UserORM.name == username).first()
    if not user:
        return templates.TemplateResponse("user_delete.html", {"request": request, "message": f"User {username} does not exists."})
        
    db.delete(user)
    db.commit()

    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("session_id")
    response.delete_cookie("username")
    response.delete_cookie("can_edit_or_delete")
    response.set_cookie(key="message_update", value="Account was deleted.", max_age=5)
    return response


@api.get("/update_user/authentication/", response_class=HTMLResponse)
@api.get("/delete_user/authentication/", response_class=HTMLResponse)
def get_authetication_form(request: Request, user: UserORM = Depends(jwt_required), next: str = "update"):
    response = templates.TemplateResponse("authentication.html", {"request": request, "next": next})
    response.headers["Cache-Control"] = "no-store"
    return response


@api.post("/update_user/authentication/", response_class=HTMLResponse)
@api.post("/delete_user/authentication/", response_class=HTMLResponse)
def authenticate_user_form(request: Request, user: UserORM = Depends(jwt_required), username: str = Form(), password: str = Form(), next: str = Form("update"), db: Session = Depends(get_db)):
    if username != request.cookies.get("username"):
        return templates.TemplateResponse("authentication.html", {"request": request, "message": "Incorrect username."})
    
    user = db.query(UserORM).filter(UserORM.name == username).first()
    if not verify_password(password, user.password):
        return templates.TemplateResponse("authentication.html", {"request": request, "message": "Incorrect password."})
    
    if next == "update":
        response = RedirectResponse("/update_user/", status_code=303)
    elif next == "delete":
        response = RedirectResponse("/delete_user/", status_code=303)
    else:
        return templates.TemplateResponse("authentication.html", {"request": request, "message": "Invalid method."})
    
    response.set_cookie(key="can_edit_or_delete", value="1", max_age=30)
    return response


def admin_user(name: str, password: str) -> bool:
    with engine.connect() as conn:
        result = conn.execute(text("""SELECT * FROM users WHERE name = :name"""),
                              {"name": name}).fetchone()
        if result and verify_password(password, result.hashed_pw):
            return result.is_admin
        return False
    

################################################ START OF HTTP REQUEST FUNCTIONS FOR TRANSACTIONS ################################################
@api.get('/transactions/', response_model=dict[str, List[Transaction]])
def load_transactions(current_user: UserORM = Depends(get_current_user), db: Session = Depends(get_db)):
    transactions = db.query(TransactionORM).filter(TransactionORM.user_id == current_user.id).all()
    if not transactions:
        raise HTTPException(status_code=404, detail=f'No transactions found for {current_user.name}.')
    
    transactions_list = [Transaction.model_validate(transaction) for transaction in transactions]
    print(transactions_list)
    return {"User transactions": transactions_list}
    

@api.post('/add_transaction/', response_model=dict[str, Transaction])
def add_transaction(purpose: str, current_user: UserORM = Depends(get_current_user), db: Session = Depends(get_db), 
                    money_earned: float | None = None, 
                    money_spent: float | None = None):
    if (money_earned is None) == (money_spent is None):
        raise HTTPException(status_code=400, detail=f'Either money_earned or money_spent must be given.')
    if money_earned is not None and money_earned <= 0:
        raise HTTPException(status_code=400, detail=f'money_earned must be positive.')
    if money_spent is not None and money_spent <= 0:
        raise HTTPException(status_code=400, detail=f'money_spent must be positive.')
    
    money_earned = money_earned if money_earned else None
    date_time_earned = datetime.now(timezone.utc) if money_earned is not None else None
    money_spent = money_spent if money_spent else None
    date_time_spent = datetime.now(timezone.utc) if money_spent is not None else None
    
    transaction = TransactionORM(user_id=current_user.id, money_earned=money_earned, date_time_earned=date_time_earned, money_spent=money_spent, date_time_spent=date_time_spent, purpose=purpose)
    db.add(transaction)
    db.commit()
    db.refresh(transaction)
    return {"Added transaction": Transaction.model_validate(transaction)}


@api.put('/update_transaction/', response_model=dict[str, Transaction])
def update_transaction(transaction_id: int, current_user: UserORM = Depends(get_current_user), db: Session = Depends(get_db),
                       money_earned: float | None = None,
                       money_spent: float | None = None,
                       purpose: str | None = None):
    if money_earned is not None and money_earned <= 0:
        raise HTTPException(status_code=400, detail=f'money_earned must be positive.')
    if money_spent is not None and money_spent <= 0:
        raise HTTPException(status_code=400, detail=f'money_spent must be positive.')
    
    transaction = db.query(TransactionORM).filter(TransactionORM.id == transaction_id).first()
    if not transaction:
        raise HTTPException(status_code=404, detail=f'Transaction {transaction_id} does not exist.')
    if transaction.user_id != current_user.id:
        raise HTTPException(status_code=403, detail=f'User {current_user.name} not allowed to modify this entry.')
    
    if money_earned is not None:
        transaction.money_earned = money_earned
        transaction.date_time_earned = datetime.now(timezone.utc)
        transaction.money_spent = None
        transaction.date_time_spent= None

    elif money_spent is not None:
        transaction.money_spent = money_spent
        transaction.date_time_spent= datetime.now(timezone.utc)
        transaction.money_earned = None
        transaction.date_time_earned = None
    
    transaction.purpose = purpose if purpose else transaction.purpose

    db.commit()
    db.refresh(transaction)
    return {"Updated transaction": Transaction.model_validate(transaction)}


@api.delete('/delete_transaction/', response_model=dict[str, Transaction])
def delete_transaction(transaction_id: int, current_user: UserORM = Depends(get_current_user), db: Session = Depends(get_db)):    
    transaction = db.query(TransactionORM).filter(TransactionORM.id == transaction_id).first()
    if not transaction:
        raise HTTPException(status_code=404, detail=f'Transaction {transaction_id} does not exist.')
    if transaction.user_id != current_user.id:
        raise HTTPException(status_code=403, detail=f'User {current_user.name} not allowed to modify this entry.')
    
    db.delete(transaction)
    db.commit()
    return {"Deleted transaction": Transaction.model_validate(transaction)}

