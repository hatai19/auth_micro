from passlib.handlers.sha2_crypt import sha256_crypt
from sqlalchemy import Integer, String
from sqlalchemy.orm import declarative_base, mapped_column, Mapped, DeclarativeBase


class Base(DeclarativeBase):
    __abstract__ = True
    id: Mapped[int]  = mapped_column( primary_key=True)


class User(Base):
    __tablename__ = "user"

    first_name = mapped_column(String)
    last_name = mapped_column(String)
    username = mapped_column(String)
    email = mapped_column(String, unique=True)
    password_hash: Mapped[str] = mapped_column()
