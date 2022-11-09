from fastapi import (
    Depends,
)
from fastapi.responses import (
    RedirectResponse,
    HTMLResponse,
    PlainTextResponse
)
from starlette.requests import Request
from fastapi.templating import Jinja2Templates

from .app import app
from .models import User
from .services import get_current_user


templates = Jinja2Templates(directory="app/static/templates")


@app.get('/')
async def index(user: User = Depends(get_current_user)):
    return PlainTextResponse(f'Hello, {user.username}!')

@app.get(
    '/sign-in',
    response_class=HTMLResponse
)
def sign_in_get(request: Request):
    return templates.TemplateResponse(
        'auth.html',
        {'request': request}
    )
