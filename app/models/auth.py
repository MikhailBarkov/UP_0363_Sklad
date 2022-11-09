from enum import Enum

from pydantic import BaseModel


class AccessLevels(int, Enum):
    LOW = 1
    MED = 2
    HIG = 3


class BaseUser(BaseModel):
    username: str
    access: AccessLevels


class UserCreate(BaseUser):
    password: str


class User(BaseUser):
    id: int

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str = 'Bearer'
