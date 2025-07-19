from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import EmailStr
from sqlalchemy.orm import Session
import pandas as pd
from jose import jwt, JWTError
from Backend_Classes import UserORM, TransactionORM, Category, JWT_TokenORM, hash_password, verify_password, SECRET_KEY, HASH_ALG
from datetime import datetime, timezone, timedelta
from database import get_db


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
    

################################################ START OF HTTP REQUEST FUNCTIONS FOR TRANSACTIONS ################################################
@api.get('/transactions/', response_class=HTMLResponse)
def load_transactions(request: Request, user: UserORM = Depends(jwt_required), db: Session = Depends(get_db)):
    username = user.name
    transactions = db.query(TransactionORM).filter(TransactionORM.user_id == user.id).all()
    if not transactions:
        response = templates.TemplateResponse("transactions.html", {"request": request, "message": f"No transactions found for {username}.", "username": username})
        response.headers["Cache-Control"] = "no-store"
        return response
    
    response = templates.TemplateResponse("transactions.html", {"request": request, "username": username, "transactions": transactions})
    response.headers["Cache-Control"] = "no-store"
    return response
    

@api.get('/add_transaction/', response_class=HTMLResponse)
def get_add_tx_form(request: Request, user: UserORM = Depends(jwt_required)):
    response = templates.TemplateResponse("add_transaction.html", {"request": request, "user_type": user.is_admin})
    response.headers["Cache-Control"] = "no-store"
    return response


@api.post('/add_transaction/', response_class=HTMLResponse)
def add_transaction(request: Request, category: str= Form(), purpose: str = Form(), 
                    user: UserORM = Depends(jwt_required), db: Session = Depends(get_db), 
                    money_earned: str | None = Form(""),
                    money_spent: str | None = Form("")):
    money_earned_val = float(money_earned) if money_earned.strip() else None
    money_spent_val = float(money_spent) if money_spent.strip() else None

    if (money_earned_val is None) == (money_spent_val is None):
        response = templates.TemplateResponse("add_transaction.html", {"request": request, "message": f"Please add an amount either for money earned or money spent."})
        return response
    if money_earned_val is not None and money_earned_val <= 0:
        response = templates.TemplateResponse("add_transaction.html", {"request": request, "message": f"Money Earned must be positive."})
        return response
    if money_spent_val is not None and money_spent_val <= 0:
        response = templates.TemplateResponse("add_transaction.html", {"request": request, "message": f"Money Spent must be positive."})
        return response
    
    if not category:
        response = templates.TemplateResponse("add_transaction.html", {"request": request, "message": f"A category must be included."})
        return response
    
    money_earned = money_earned_val
    date_time_earned = datetime.now(timezone.utc) if money_earned_val else None
    money_spent = money_spent_val
    date_time_spent = datetime.now(timezone.utc) if money_spent_val else None
    
    transaction = TransactionORM(user_id=user.id, money_earned=money_earned, date_time_earned=date_time_earned, 
                                 money_spent=money_spent, date_time_spent=date_time_spent, category=category, purpose_details=purpose)
    db.add(transaction)
    db.commit()
    db.refresh(transaction)

    response = templates.TemplateResponse("add_transaction.html", {"request": request, "success_message": f"Transaction successfully added."})
    return response


@api.get('/update_transaction/', response_class=HTMLResponse)
def get_update_tx_form(request: Request, user: UserORM = Depends(jwt_required)):
    response = templates.TemplateResponse("update_transaction.html", {"request": request, "user_type": user.is_admin})
    response.headers["Cache-Control"] = "no-store"
    return response


@api.post('/update_transaction/', response_class=HTMLResponse)
def update_transaction(request: Request, 
                       transaction_id: int = Form(), 
                       user: UserORM = Depends(jwt_required), 
                       db: Session = Depends(get_db),
                       method_override: str = Form(),
                       money_earned: str | None = Form(""),
                       money_spent: str | None = Form(""),
                       category: Category | None = Form(),
                       purpose: str | None = Form("")):
    if method_override != "put":
        raise HTTPException(status_code=405, detail="Method not allowed.")
    
    money_earned_val = float(money_earned) if money_earned.strip() else None
    money_spent_val = float(money_spent) if money_spent.strip() else None
    
    if money_earned_val is not None and money_earned_val <= 0:
        return templates.TemplateResponse('update_transaction.html', {"request": request, "message": f"Money Earned must be positive."})
    if money_spent_val is not None and money_spent_val <= 0:
        return templates.TemplateResponse('update_transaction.html', {"request": request, "message": f"Money Spent must be positive."})
    
    if not category:
        return templates.TemplateResponse("add_transaction.html", {"request": request, "message": f"A category must be included."})
    
    transaction = db.query(TransactionORM).filter(TransactionORM.id == transaction_id).first()
    if not transaction:
        return templates.TemplateResponse('update_transaction.html', {"request": request, "message": f"Transaction {transaction_id} does not exist."})
    if transaction.user_id != user.id:
        return templates.TemplateResponse('update_transaction.html', {"request": request, "message": f"User {user.name} not allowed to modify this entry."})
    
    if money_earned_val:
        transaction.money_earned = money_earned_val
        transaction.date_time_earned = datetime.now(timezone.utc)
        transaction.money_spent = None
        transaction.date_time_spent= None

    elif money_spent_val:
        transaction.money_spent = money_spent_val
        transaction.date_time_spent= datetime.now(timezone.utc)
        transaction.money_earned = None
        transaction.date_time_earned = None
    
    transaction.category = category
    transaction.purpose_details = purpose if purpose else transaction.purpose_details

    db.commit()
    db.refresh(transaction)

    response = templates.TemplateResponse('update_transaction.html', {"request": request, "success_message": f"Transaction #{transaction_id} updated successfully."})
    return response


@api.get('/delete_transaction/', response_class=HTMLResponse)
def get_delete_tx_form(request: Request, user: UserORM = Depends(jwt_required)):
    response = templates.TemplateResponse('delete_transaction.html', {"request": request, "user_type": user.is_admin})
    response.headers["Cache-Control"] = "no-store"
    return response


@api.post('/delete_transaction/', response_class=HTMLResponse)
def delete_transaction(request: Request, method_override: str = Form(), transaction_id: int = Form(), user: UserORM = Depends(jwt_required), db: Session = Depends(get_db)):  
    if method_override != "delete":
        raise HTTPException(status_code=405, detail="Method not allowed.")

    transaction = db.query(TransactionORM).filter(TransactionORM.id == transaction_id).first()
    if not transaction:
        return templates.TemplateResponse('delete_transaction.html', {"request": request, "message": f"Transaction #{transaction_id} does not exist."})
    if transaction.user_id != user.id:
        return templates.TemplateResponse('delete_transaction.html', {"request": request, "message": f"User {user.name} not allowed to modify this entry."})
    
    db.delete(transaction)
    db.commit()

    if user.is_admin:
        response = RedirectResponse("/hub-admin/", status_code=303)
        response.set_cookie(key="success_message", value="Transaction deleted.")
        return response
    
    response = RedirectResponse("/hub/", status_code=303)
    response.set_cookie(key="success_message", value="Transaction deleted.")
    return response


################################################ START OF HTTP REQUEST FUNCTIONS FOR ANALYSIS ################################################
@api.get('/transactions/money_earned/', response_class=HTMLResponse)
def get_monthly_money_earned(request: Request, user: UserORM = Depends(jwt_required), db: Session = Depends(get_db)):
    transactions = db.query(TransactionORM).filter((TransactionORM.user_id == user.id) & (TransactionORM.money_earned.isnot(None)))

    df = pd.read_sql(transactions.statement, db.bind)
    df['date_time_earned'] = pd.to_datetime(df['date_time_earned'])
    df['month'] = df['date_time_earned'].dt.to_period("M")

    grouped = df.groupby('month')['money_earned'].sum().reset_index()
    grouped['month'] = grouped['month'].dt.strftime('%B %Y')

    response = templates.TemplateResponse("money_earned.html", {"request": request, "earnings": grouped.to_dict(orient="records")})
    return response


@api.get('/transactions/money_spent/', response_class=HTMLResponse)
def get_monthly_money_spent(request: Request, user: UserORM = Depends(jwt_required), db: Session = Depends(get_db)):
    transactions = db.query(TransactionORM).filter((TransactionORM.user_id == user.id) & (TransactionORM.money_spent.isnot(None)))

    df = pd.read_sql(transactions.statement, db.bind)
    df['date_time_spent'] = pd.to_datetime(df['date_time_spent'])
    df['month'] = df["date_time_spent"].dt.to_period("M")

    grouped = df.groupby('month')['money_spent'].sum().reset_index()
    grouped['month'] = grouped['month'].dt.strftime('%B %Y')

    response = templates.TemplateResponse('money_spent.html', {"request": request, "expenditures": grouped.to_dict(orient="records")})
    return response


'''@api.get('/transactions/money_earned/analysis/')

@api.get('/transactions/money_spent/analysis/')'''