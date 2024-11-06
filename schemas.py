from pydantic import BaseModel
from datetime import datetime

class UserBase(BaseModel):
    email: str

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int

    class Config:
        orm_mode = True

class ReferralCreate(BaseModel):
    code: str
    expiration_date: datetime

class ReferralResponse(BaseModel):
    id: int
    code: str
    expiration_date: datetime
    owner_id: int
    is_active: bool

    class Config:
        orm_mode = True

class User(BaseModel):
    id: int
    email: str
    is_active: bool

    class Config:
        orm_mode = True





