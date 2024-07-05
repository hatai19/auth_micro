import os
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from src.auth.config import oauth2_scheme, bcrypt_context, DatabaseDep
from src.auth.exceptions import handle_integrity_error, raise_invalid_credentials_exception, validation_exception, \
    no_token_exception
from src.auth.models import User
from src.auth.repository import register_user_repository, select_user_repository
from src.database import get_db


async def register_user_service(create_user, db):
    try:
        await register_user_repository(create_user, db)
    except IntegrityError as e:
        handle_integrity_error(e)


async def authenticate_user(db, username:str, password:str):
    user = await select_user_repository(db, username)
    if not user or not bcrypt_context.verify(password, user.password_hash):
        raise_invalid_credentials_exception()
    return user


async def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id, }
    expires = datetime.now() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, os.getenv('SECRET_KEY'), algorithm=os.getenv('ALGORITHM'))


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)],
                           db: DatabaseDep):
    try:
        payload = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=[os.getenv('ALGORITHM')])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        expire = payload.get('exp')
        user = await select_user_repository(db, username)
        if username is None or user_id is None:
            validation_exception()
        if expire is None:
            no_token_exception()
        return {
            'username': user.username,
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
        }
    except JWTError:
        validation_exception()


