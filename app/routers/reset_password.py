from typing import Optional, Union

from app.config import templates
from app.database.database import get_db
from app.internal.security.reset_password import (
    BackgroundTasks ,send_mail)
from app.internal.security.ouath2 import (
    authenticate_user, create_jwt_token,
    check_jwt_token, update_password)
from app.internal.security.schema import (
    ForgotPassword, LoginUser, ResetPassword)
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse
from starlette.status import HTTP_302_FOUND



router = APIRouter(
    prefix="",
    tags=["/reset_password"],
    responses={404: {"description": "Not found"}},
)



@router.get("/forgot-password")
async def forgot_password_form(
            request: Request) -> templates:
    return templates.TemplateResponse("forgot_password.html", {
        "request": request,
    })


@router.post('/forgot-password')
async def forgot_password(
        request: Request, background_tasks: BackgroundTasks,
            db: Session = Depends(get_db)) -> templates:
    form = await request.form()
    form_dict = dict(form)
    # creating pydantic schema object out of form data

    user = ForgotPassword(**form_dict)
    """
    Validaiting form data,
    if user exist in database,
    if email correct.
    """
    if user:
        user =  await authenticate_user(db, user, email=True)
        if user:
            user.token = create_jwt_token(LoginUser(
                username=user.username, password=user.password),
                JWT_MIN_EXP=60*24)
            await send_mail(db, user, background_tasks)
            return templates.TemplateResponse("home.html", {
                "request": request,
                "message": "Email for ressting password was sent"})
    return templates.TemplateResponse("forgot_password.html", {
            "request": request,
            "message": 'Please check your credentials'
        })


@router.get("/reset-password")
async def reset_password_form(
        request: Request, token: Optional[str] = ""
        ) -> templates:
    if token:
        return templates.TemplateResponse("reset_password.html", {
        "request": request,
    })
    return RedirectResponse("/login?message=You did not supply a verification token")


@router.post("/reset-password")
async def reset_password(
        request: Request, token:
        str = "", db: Session = Depends(get_db)
        ) -> RedirectResponse:
    db_user = await check_jwt_token(db, token, reset_password=True)
    form = await request.form()
    form_dict = dict(form)
    validated = True
    if not form_dict['username'] == db_user.username:
        validated = False
    try:
        # creating pydantic schema object out of form data
        user = ResetPassword(**form_dict)
    except ValueError:
        validated = False
    if not validated:
            return templates.TemplateResponse("reset_password.html", {
        "request": request,
        "message": 'Please check your credentials'
    })
    await update_password(db, db_user, user.password)
    return RedirectResponse(
        url="/login?message=Success reset password",
        status_code=HTTP_302_FOUND)
