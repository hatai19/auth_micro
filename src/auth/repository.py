from sqlalchemy import insert, delete, update, select

from src.auth.config import bcrypt_context
from src.auth.models import User


async def register_user_repository(create_user, db):
    await db.execute(insert(User).values(
        first_name=create_user.first_name,
        last_name=create_user.last_name,
        email=create_user.email,
        password_hash=bcrypt_context.hash(create_user.password),
        username=create_user.username,
        ))
    await db.commit()


async def delete_user_repository(db, user):
    await db.execute(delete(User).where(User.id == user['id']))
    await db.commit()


async def update_user_repository(db, user, update_user):
    query = update(User).where(User.id == user['id']).values(
        username=update_user.username,
        email=update_user.email,
        first_name=update_user.first_name,
        last_name=update_user.last_name,
        password_hash=bcrypt_context.hash(update_user.password),
    )
    await db.execute(query)
    await db.commit()


async def select_user_repository(db, username):
    result = await db.scalar(select(User).where(User.username == username))
    return result
