from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy import select, insert, delete, update
from starlette.status import HTTP_400_BAD_REQUEST

from src.auth.models import User
from src.auth.schemas import CreateUser
from src.database import get_db
from typing import Annotated
from sqlalchemy.ext.asyncio import AsyncSession

from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError

auth_router = APIRouter(prefix='/auth', tags=['auth'])
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")
SECRET_KEY = '8ec1cf430ef3e345f60179f29498fe67d6bc03af393d907fb959cb0328efc850'
ALGORITHM = 'HS256'


async def authanticate_user(db: Annotated[AsyncSession, Depends(get_db)], username: str, password: str):
    user = await db.scalar(select(User).where(User.username == username))
    if not user or not bcrypt_context.verify(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id, }
    expires = datetime.now() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        expire = payload.get('exp')
        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Could not validate user'
            )
        if expire is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No access token supplied"
            )
        if datetime.now() > datetime.fromtimestamp(expire):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token expired!"
            )

        return {
            'username': username,
            'id': user_id,
        }
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate user'
        )


@auth_router.post("/register")
async def register_user(create_user: CreateUser, db: Annotated[AsyncSession, Depends(get_db)],):
    if await db.scalar(select(User).where(User.email == create_user.email)):
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST,detail=' Email уже используется')
    await db.execute(insert(User).values(
        first_name=create_user.first_name,
        last_name=create_user.last_name,
        email=create_user.email,
        password_hash=bcrypt_context.hash(create_user.password),
        username=create_user.username,
    ))
    await db.commit()
    return {
        'status_code': status.HTTP_201_CREATED,
        'transaction': 'Successful'
    }


@auth_router.post('/token')
async def login(db: Annotated[AsyncSession, Depends(get_db)], form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = await authanticate_user(db, form_data.username, form_data.password, )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate user'
        )

    token = await create_access_token(user.username, user.id,
                                expires_delta=timedelta(minutes=20))
    return {
        'access_token': token,
        'token_type': 'bearer'
    }


@auth_router.get("/profile")
async def read_user_profile(current_user: User = Depends(get_current_user), ):
    return current_user


@auth_router.delete("/profile/delete")
async def delete_user_profile(db: Annotated[AsyncSession, Depends(get_db)], user: User = Depends(get_current_user),):
    await db.execute(delete(User).where(User.id == user['id']))
    await db.commit()
    return {
        'message': 'User profile successfully deleted'
    }


@auth_router.put("/profile/update")
async def update_user_profile(update_data: CreateUser, db: Annotated[AsyncSession, Depends(get_db)],
                               user: User = Depends(get_current_user)):
    query = update(User).where(User.id == user['id']).values(
        username=update_data.username,
        email=update_data.email
    )
    await db.execute(query)
    await db.commit()
    return {
        'message': 'User profile successfully updated'
    }