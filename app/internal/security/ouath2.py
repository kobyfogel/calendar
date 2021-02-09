from datetime import datetime, timedelta
from typing import Union

from app.config import JWT_ALGORITHM, JWT_KEY, JWT_MIN_EXP
from passlib.context import CryptContext
from app.database.models import User
from app.internal.security.schema import ForgotPassword
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
import jwt
from jwt.exceptions import InvalidSignatureError
from sqlalchemy.orm import Session
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.status import HTTP_401_UNAUTHORIZED
from .schema import LoginUser, CurrentUser


pwd_context = CryptContext(schemes=["bcrypt"])
oauth_schema = OAuth2PasswordBearer(tokenUrl="/login")


async def update_password(db: Session, db_user: User, user_password: str):
    hashed_password = get_hashed_password(user_password)
    db_user.password = hashed_password
    db.commit()


async def get_db_user_by_username(db: Session, username: str) -> User:
    """Checking database for user by username field"""
    user = db.query(User).filter_by(username=username).first()
    return user


def get_hashed_password(password) -> str:
    """Hashing user password"""
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password) -> bool:
    """Verifying password and hashed password are equal"""
    return pwd_context.verify(plain_password, hashed_password)


async def authenticate_user(
        db: Session, user: Union[LoginUser, ForgotPassword], email: bool = False) -> Union[LoginUser, ForgotPassword, bool]:
    """Verifying user is in database and password is correct"""
    db_user = await get_db_user_by_username(db=db, username=user.username)
    if db_user:
        if email:
            if db_user.email == user.email:
                return ForgotPassword(
                    username=user.username, password=db_user.password, email=db_user.email)
            else:
                return False
        if verify_password(user.password, db_user.password):
            return LoginUser(
                username=user.username, password=db_user.password)
    return False


def create_jwt_token(
        user: LoginUser, JWT_MIN_EXP: int = JWT_MIN_EXP,
        JWT_KEY: str = JWT_KEY) -> str:
    """Creating jwt-token out of user unique data"""
    expiration = datetime.utcnow() + timedelta(minutes=JWT_MIN_EXP)
    jwt_payload = {
        "sub": user.username,
        "hashed_password": user.password,
        "exp": expiration}
    jwt_token = jwt.encode(
        jwt_payload, JWT_KEY, algorithm=JWT_ALGORITHM)
    return jwt_token


async def check_jwt_token(
    db: Session,
    token: str = Depends(oauth_schema), path: bool = None,
        reset_password: bool = False) -> CurrentUser:
    """
    Check whether JWT token is correct. Returns User object if yes.
    Returns None or raises HTTPException,
    depanding which depandency activated this function.
    """
    try:
        jwt_payload = jwt.decode(
            token, JWT_KEY, algorithms=JWT_ALGORITHM)
        jwt_username = jwt_payload.get("sub")
        jwt_hashed_password = jwt_payload.get("hashed_password")
        db_user = await get_db_user_by_username(db, username=jwt_username)
        if db_user and db_user.password == jwt_hashed_password:
            if reset_password:
                return db_user
            return CurrentUser(**db_user.__dict__)
        else:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                headers=path,
                detail="Your token is incorrect. Please log in again")
    except InvalidSignatureError:
        raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                headers=path,
                detail="Your token is incorrect. Please log in again")
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            headers=path,
            detail="Your token has expired. Please log in again")
    except jwt.DecodeError:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            headers=path,
            detail="Your token is incorrect. Please log in again")


async def get_cookie(request: Request) -> str:
    """
    Extracts jwt from HTTPONLY cookie, if exists.
    Raises HTTPException if not.
    """
    if 'Authorization' in request.cookies:
        return request.cookies['Authorization']
    raise HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        headers=request.url.path,
        detail="Please log in to enter this page")


async def my_exception_handler(
        request: Request,
        exc: HTTP_401_UNAUTHORIZED) -> RedirectResponse:
    """
    Whenever HTTP_401_UNAUTHORIZED is raised,
    redirecting to login route, with original requested url,
    and details for why original request failed.
    """
    paramas = f"?next={exc.headers}&message={exc.detail}"
    url = f"/login{paramas}"
    response = RedirectResponse(url=url)
    response.delete_cookie('Authorization')
    return response
