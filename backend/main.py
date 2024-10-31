from typing import Annotated
from datetime import datetime, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException, status, APIRouter

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from uvicorn import run
from sqlmodel import SQLModel, Field, create_engine
from pydantic import BaseModel, Field as PDField
from sqlalchemy.orm import sessionmaker, Session
import hashlib
import jwt
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext

app = FastAPI()

SECRET_KEY = "d29b0518d40de3bdc7cd369265bb4ff3daec082666f0923979ae8d44f2c8946f"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ENGINE = create_engine("sqlite:///mydb.db", echo=True)
SESSION = sessionmaker(bind=ENGINE)

OAUTH2_SCHEME = OAuth2PasswordBearer(tokenUrl="token")
PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

from models import Token, TokenData, User, User
from helpful import (
    authenticate_user,
    create_access_token,
    get_current_active_user,
    get_current_user,
    get_password_hash,
    get_session,
    verify_password,
)

auth_router = APIRouter(prefix="/users", tags=["users"])
product_router = APIRouter(prefix="/prod", tags=["prod"])


@product_router.get("/users/me", response_model=User)
@auth_router.get("/me", response_model=User)
async def read_users_me(
    current_user: Annotated[
        User,
        Depends(get_current_active_user),
    ]
):
    return {"current_user": current_user}


@product_router.get(
    "/items/",
)
async def read_items(
    current_user: Annotated[
        User,
        Depends(get_current_active_user),
    ]
):
    return {"current_user": current_user}


class Item(BaseModel):
    name: str = PDField(examples=["Foo"])
    description: int | str | None = PDField(
        default=None, examples=["A very nice Item", 124]
    )
    price: float = PDField(examples=[35.4])
    tax: float | None = PDField(default=None, examples=[3.2])


@product_router.put("/items/{item_id}", summary="ОНОВИТИ ЕЛЕМЕНТ")
async def update_item(item_id: int, item: Item):
    """
    Create an item with all the information:

    - **name**: each item must have a name
    - **description**: a long description
    - **price**: required
    - **tax**: if the item doesn't have tax, you can omit this
    - **tags**: a set of unique tag strings for this item
    """
    results = {"item_id": item_id, "item": item}
    return results


@auth_router.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


def main():
    SQLModel.metadata.drop_all(ENGINE)
    SQLModel.metadata.create_all(ENGINE)

    with SESSION.begin() as session:
        session.add(
            User(
                username="vasya",
                email="vasya@gmail.com",
                hashed_password=get_password_hash("123456qwerty"),
            )
        )
    app.include_router(auth_router)
    app.include_router(product_router)
    run(app)
