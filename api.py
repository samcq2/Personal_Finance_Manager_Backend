from pydantic import BaseModel
import logging
from fastapi import FastAPI
from datetime import timedelta, datetime
from typing import List, Optional
import uuid
import requests
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, APIRouter, Query, HTTPException, status, Depends, Header, BackgroundTasks, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
import psycopg2
from psycopg2 import sql
from psycopg2 import extras
from fastapi.middleware.cors import CORSMiddleware
import bcrypt
from enum import Enum
import jwt as jwt_lib
import redis
import stripe
from stripe.api_resources.event import Event
from fastapi import Body
import json

class User(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    user_id: int
    full_name: str
    email: str

def get_db_connection():
    conn = psycopg2.connect(
        database='personal_finance_db',
        user='Sam.C.Q',
        password='SGKCNWTO3H4K5N7M5',
        host='localhost',
        port='5432',
    )
    try:
        yield conn
    finally:
        conn.close()

app = FastAPI()

TOKEN_EXPIRATION_SECONDS = 60 * 60
TOKEN_EXPIRATION_SECONDS_REMEMBER_ME = 60 * 60 * 24 * 30

REDIS_HOST = 'localhost'
REDIS_PORT = '6379'

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)

origins = ['*']

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

login_security = HTTPBasic()

def get_current_user(Authorization: str = Header(None)):
    if not Authorization:
        raise HTTPException(
            status_code=400, detail="Authorization header missing")
    try:
        bearer, token = Authorization.split(" ")
        if bearer != "Bearer":
            raise HTTPException(
                status_code=400, detail="Authorization header invalid")

        user_id = redis_client.get(token)
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        return int(user_id)
    except KeyError as e:
        raise HTTPException(status_code=400, detail="Token is invalid")
    
def verify_password(email: str, password: str, conn=Depends(get_db_connection)):
    cur = conn.cursor()

    cur.execute("SELECT password FROM users where email = %s", [email])
    res = cur.fetchone()
    if res == None:
        return None
    hashed_password = res[0]

    hashed_password = bytes.fromhex(hashed_password[2:])

    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        return User(email=email, password=password)
    else:
        return None

def create_access_token(data: dict, secret: str, algorithm: str = 'HS256', expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()

    to_encode.update({'unique_id': str(uuid.uuid4())})

    encoded_jwt = jwt_lib.encode(to_encode, secret, algorithm=algorithm)

    return encoded_jwt

@app.get("/")
def root():
    return "working"

@app.get("/get_full_name")
def get_full_name(user_id: int = Depends(get_current_user), conn=Depends(get_db_connection)):
    cur = conn.cursor()
    cur.execute("SELECT full_name FROM users WHERE user_id = %s", [user_id])
    res = cur.fetchone()
    cur.close()

    if not res:
        raise HTTPException(status_code=404, detail="Full name not found")

    return {'full_name': res[0]}

@app.post("/create_account")
def create_account(request_data: dict, credentials: HTTPBasicCredentials = Depends(login_security), conn=Depends(get_db_connection)):
    try:
        cur = conn.cursor()

        email = credentials.username
        password = credentials.password
        full_name = request_data.get('full_name')

        cur.execute("SELECT user_id from users where email = %s", [email])
        res = cur.fetchone()
        if res is not None:
            raise HTTPException(status_code=400, detail='Email is already taken')

        cur.execute("SELECT user_id FROM users WHERE full_name = %s", [full_name])
        res = cur.fetchone()
        if res is not None:
            raise HTTPException(status_code=400, detail='Full name is already taken')

        byte_password = password.encode()
        hashed_password = bcrypt.hashpw(byte_password, bcrypt.gensalt())

        # Make sure the number of placeholders matches the number of parameters
        cur.execute("INSERT INTO users (email, full_name, password) VALUES (%s, %s, %s)",
                    (email, full_name, hashed_password))  # Use a tuple here instead of a list
        conn.commit()
        cur.execute("SELECT * FROM users where email = %s", [email])
        res = cur.fetchone()
        user_id = res[0]

        return {'message': 'success', 'user_id': user_id, 'user': res, 'full_name': full_name}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/login")
def login(credentials: HTTPBasicCredentials = Depends(login_security), conn=Depends(get_db_connection)):
    email = credentials.username
    password = credentials.password

    cur = conn.cursor()
    user = verify_password(email, password, conn)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    cur.execute("SELECT user_id FROM users WHERE email = %s", [email])
    res = cur.fetchone()
    user_id = res[0]

    # Get all tokens associated with the email
    tokens = redis_client.keys( "*")

    # Delete the old tokens
    for token in tokens:
        if token.decode('utf-8') != email:
            redis_client.delete(token)

    access_token = create_access_token({}, "secret")
    redis_client.set(access_token, user_id, ex=TOKEN_EXPIRATION_SECONDS_REMEMBER_ME)

    return {"access_token": access_token, "user_id": user_id}

@app.post("/logout")
def logout(Authorization: str = Header(None)):
    if not Authorization:
        raise HTTPException(
            status_code=400, detail="Authorization header missing")

    bearer, token = Authorization.split(" ")
    if bearer != "Bearer":
        raise HTTPException(
            status_code=400, detail="Authorization header invalid")

    if redis_client.get(token) is None:
        return {'message': 'you are not signed in'}

    redis_client.delete(token)
    return {'message': 'signed out successfully'}

@app.get("/get_all_users", response_model=List[UserResponse])
def get_all_users(conn=Depends(get_db_connection)):
    try:
        cur = conn.cursor()
        cur.execute("SELECT user_id, full_name, email FROM users")
        rows = cur.fetchall()
        users = []
        for row in rows:
            user_id, full_name, email = row
            users.append(UserResponse(user_id=user_id, full_name=full_name, email=email))
        return users
    except Exception as e:
        if e != {} :
            raise e
        raise HTTPException(status_code=500,detail='database error')