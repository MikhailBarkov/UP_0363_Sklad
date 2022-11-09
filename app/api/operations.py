from fastapi import (
    APIRouter,
    Depends,
)

from .. import models
from ..services import OperationsService
from ..services.auth import get_current_user


router = APIRouter(prefix='/operations')


@router.get('/{page}')
def get_products(
    page: int,
    user: models.User = Depends(get_current_user),
    service: OperationsService = Depends(),
):
    return service.get_products(
        user.access,
        page
    )
