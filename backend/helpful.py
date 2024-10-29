from typing import Annotated
from datetime import datetime, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException, status

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from uvicorn import run
from sqlmodel import SQLModel, Field, create_engine
from sqlalchemy.orm import sessionmaker, Session
import hashlib
import jwt
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from main import (
    SESSION,
    PWD_CONTEXT,
    OAUTH2_SCHEME,
    User,
    SECRET_KEY,
    ALGORITHM,
    TokenData,
)


def get_session():
    with SESSION.begin() as session:
        yield session


def verify_password(plain_password, hashed_password):
    return PWD_CONTEXT.verify(plain_password, hashed_password)


def get_password_hash(password):
    return PWD_CONTEXT.hash(password)


def get_user(session, username: str):
    return session.get(User, username)
    if user:
        return User(**user.model_dump())


def authenticate_user(username: str, password: str):
    with SESSION.begin() as session:
        user = get_user(session, username)
        print(f"{user=}")
        if not user:
            return False
        if not verify_password(password, user.hashed_password):
            return False
        return User(**user.model_dump())


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    with SESSION.begin() as session:
        user = get_user(session, username=token_data.username)
        if user is None:
            raise credentials_exception
        return User(**user.model_dump())


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
