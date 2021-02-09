from app.config import PSQL_ENVIRONMENT
from app.database import models
from app.database.database import engine, get_db
from app.dependencies import (
    logger, MEDIA_PATH, STATIC_PATH, templates)
from app.internal import daily_quotes, json_data_loader
from app.internal.security.ouath2 import my_exception_handler
from app.routers import (
    agenda, calendar, categories, currency, dayview, email,
    event, reset_password, invitation, login, logout, profile,
    register, search, telegram, whatsapp
)
from fastapi import Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.status import HTTP_401_UNAUTHORIZED
from sqlalchemy.orm import Session
from tests import security_testing_routes


def create_tables(engine, psql_environment):
    if 'sqlite' in str(engine.url) and psql_environment:
        raise models.PSQLEnvironmentError(
            "You're trying to use PSQL features on SQLite env.\n"
            "Please set app.config.PSQL_ENVIRONMENT to False "
            "and run the app again."
        )
    else:
        models.Base.metadata.create_all(bind=engine)


create_tables(engine, PSQL_ENVIRONMENT)
app = FastAPI()
app.mount("/static", StaticFiles(directory=STATIC_PATH), name="static")
app.mount("/media", StaticFiles(directory=MEDIA_PATH), name="media")

app.include_router(security_testing_routes.router)
app.include_router(profile.router)
app.include_router(event.router)
app.include_router(agenda.router)
app.include_router(register.router)
app.include_router(email.router)
app.include_router(invitation.router)
app.include_router(login.router)
app.include_router(logout.router)
app.include_router(reset_password.router)

app.add_exception_handler(HTTP_401_UNAUTHORIZED, my_exception_handler)

json_data_loader.load_to_db(next(get_db()))

app.logger = logger


routers_to_include = [
    reset_password.router,
    agenda.router,
    calendar.router,
    categories.router,
    currency.router,
    dayview.router,
    email.router,
    event.router,
    invitation.router,
    login.router,
    logout.router,
    profile.router,
    register.router,
    search.router,
    telegram.router,
    whatsapp.router,
    security_testing_routes.router,
]

for router in routers_to_include:
    app.include_router(router)


# TODO: I add the quote day to the home page
# until the relevant calendar view will be developed.
@app.get("/")
@logger.catch()
async def home(request: Request, db: Session = Depends(get_db)):
    quote = daily_quotes.quote_per_day(db)
    return templates.TemplateResponse("home.html", {
        "request": request,
        "message": "Hello, World!",
        "quote": quote
    })
