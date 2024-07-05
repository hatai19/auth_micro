from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError


def handle_integrity_error(error: IntegrityError):
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail='Данный email уже используется.'
    )


def raise_invalid_user_exception():
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate user'
    )


def raise_invalid_credentials_exception():
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Неверные данные для аутентификации",
        headers={"WWW-Authenticate": "Bearer"},
    )


def validation_exception():
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Не удалось подтвердить пользователя '
    )


def no_token_exception():
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Токен не был предоставлен"
    )