from fastapi import (
    APIRouter,
    Depends,
)
from fastapi.responses import (
    RedirectResponse,
)
from fastapi.security import OAuth2PasswordRequestForm

from ..models import (
    User,
    UserCreate,
)
from ..services import (
    AuthService,
    get_current_user,
)


router = APIRouter(prefix='/auth')


@router.post('/sign-in')
async def sign_in_post(
    from_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthService = Depends()
):
    token = service.authenticate_user(
        from_data.username,
        from_data.password
    )

    response = RedirectResponse(
        '/',
        status_code=303
    )
    response.set_cookie(
        key='access_token',
        value=f'{token.token_type} {token.access_token}',
        httponly=True
    )
    return response


@router.post('/sign-up')
async def sign_up(
    user_data: UserCreate,
    service: AuthService = Depends()
):
    token = service.register_new_user(user_data)

    response = RedirectResponse(
        '/sign-up',
        status_code=303
    )
    response.set_cookie(
        key='access_token',
        value=f'{token.token_type} {token.access_token}',
        httponly=True
    )
    return response


@router.get('/user', response_model=User)
async def get_user(user: User = Depends(get_current_user)):
    return user
