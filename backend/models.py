from sqlmodel import SQLModel, Field


class Token(SQLModel):
    access_token: str
    token_type: str


class TokenData(SQLModel):
    username: str | None = None


class User(SQLModel, table=True):
    username: str = Field(primary_key=True)
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    hashed_password: str
