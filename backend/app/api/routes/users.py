from typing import List

from fastapi import APIRouter, Body, Depends, HTTPException, Path
from starlette.status import HTTP_201_CREATED, HTTP_404_NOT_FOUND

from app.models.user import UserCreate, UserPublic
from app.api.dependencies.database import get_repository
from app.db.repositories.user import UsersRepository
from app.api.dependencies.database import get_repository

router = APIRouter()

@router.post("/", response_model=UserPublic, name="users:register-new-user", status_code=HTTP_201_CREATED)
async def register_new_user(
    new_user: UserCreate = Body(..., embed=True),
    user_repo: UsersRepository = Depends(get_repository(UsersRepository))
) -> UserPublic:
    created_user = await user_repo.register_new_user(new_user=new_user)

    return created_user