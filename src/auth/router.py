import os
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

from sqlalchemy import insert, delete, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.config import oauth2_scheme, bcrypt_context, DatabaseDep
from src.auth.exceptions import raise_invalid_user_exception
from src.auth.repository import delete_user_repository, update_user_repository
from src.auth.service import authenticate_user, create_access_token, get_current_user, register_user_service
from src.auth.models import User
from src.auth.schemas import CreateUser, UserSchema, GetUser, UpdateUser
from src.database import get_db

auth_router = APIRouter(prefix='/auth', tags=['auth'])


@auth_router.post("/register", response_model=CreateUser)
async def register_user(create_user: CreateUser, db: DatabaseDep):
    await register_user_service(create_user, db)
    return create_user


@auth_router.post('/token')
async def login(db: DatabaseDep, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise_invalid_user_exception()

    token = await create_access_token(user.username, user.id,
                                      expires_delta=timedelta(minutes=int(os.getenv('TOKEN_LIFETIME'))))
    return {
        'access_token': token,
        'token_type': 'bearer'
    }


@auth_router.get("/profile", response_model=GetUser)
async def read_user_profile(current_user: User = Depends(get_current_user)):
    return current_user


@auth_router.delete("/profile/delete")
async def delete_user_profile(db: Annotated[AsyncSession, Depends(get_db)], user: User = Depends(get_current_user)):
    await delete_user_repository(db, user)
    return {
        'message': 'Пользователь успешно удален'
    }


@auth_router.put("/profile/update", response_model=UpdateUser)
async def update_user_profile(update_user: UpdateUser, db: Annotated[AsyncSession, Depends(get_db)],
                              user: User = Depends(get_current_user)):
    await update_user_repository(db, user, update_user)
    return update_user
