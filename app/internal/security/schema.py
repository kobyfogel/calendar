from typing import List, Optional, Union

from app.database.models import UserEvent
from pydantic import BaseModel, validator


class LoginUser(BaseModel):
    """
    Validating fields types
    Returns a User object for signing in.
    """
    username: str
    password: str

    class Config:
        orm_mode = True


class CurrentUser(BaseModel):
    """
    Security dependencies will return this object,
    instead of db object.
    Returns all User's parameters, except password.
    """
    id: int
    username: str
    full_name: str
    email: str
    language: str = None
    description: str = None
    avatar: str
    telegram_id: str = None
    events = Optional[List[UserEvent]]

    class Config:
        orm_mode = True
        arbitrary_types_allowed = True


class ForgotPassword(BaseModel):
    """
    BaseModel for collecting and verifying user
    details sending a token via email
    """
    username: str
    email: str
    password: Optional[str] = None
    token: Optional[str] = None

    class Config:
        orm_mode = True


MIN_FIELD_LENGTH = 3
MAX_FIELD_LENGTH = 20


class ResetPassword(BaseModel):
    """
    Validating fields types
    """
    username: str
    password: str
    confirm_password: str

    class Config:
        orm_mode = True


    @validator('confirm_password')
    def passwords_match(
            cls, confirm_password: str,
            values: BaseModel) -> Union[ValueError, str]:
        """Validating passwords fields identical."""
        if 'password' in values and confirm_password != values['password']:
            raise ValueError
        return confirm_password


    @validator('password')
    def password_length(cls, password: str) -> Union[ValueError, str]:
        """Validating password length is legal"""
        if not (MIN_FIELD_LENGTH < len(password) < MAX_FIELD_LENGTH):
            raise ValueError
        return password