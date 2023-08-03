from pydantic import BaseModel
from fastapi import FastAPI
from datetime import timedelta, datetime
from typing import List, Optional
import uuid
import requests
from fastapi.middleware.cors import CORSMiddleware
# from repertorio import Repertorio
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
    permissions: str

class UserResponse(BaseModel):
    user_id: int
    full_name: str
    email: str
    user_type: str
    credits: int

def get_db_connection():
    conn = psycopg2.connect(
        database='bandsoc_db',
        user='postgres',
        password='68&kh50C5W31',
        host='bandsoc-db.cfflfq6deazw.eu-west-2.rds.amazonaws.com',
        port='5432',
    )
    try:
        yield conn
    finally:
        conn.close()

app = FastAPI()

TOKEN_EXPIRATION_SECONDS = 60 * 60  # 1 hour
TOKEN_EXPIRATION_SECONDS_REMEMBER_ME = 60 * 60 * 24 * 30  # 1 month

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

        # redis_client.expire(token, TOKEN_EXPIRATION_SECONDS_REMEMBER_ME)
        return int(user_id)
    except KeyError as e:
        raise HTTPException(status_code=400, detail="Token is invalid")
    
def verify_password(email: str, password: str, conn=Depends(get_db_connection)):
    cur = conn.cursor()

    # try to find the email from the SQL database, if it exists get password and compare
    cur.execute("SELECT password, type FROM users where email = %s", [email])
    res = cur.fetchone()
    if res == None:
        return None
    hashed_password = res[0]

    # hased password is stored in hex in the db, so we convert it to byte string
    hashed_password = bytes.fromhex(hashed_password[2:])
    account_type = res[1]

    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        return User(email=email, password=password, permissions=account_type)
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
