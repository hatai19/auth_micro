from sqlalchemy.orm import mapped_column, Mapped, DeclarativeBase

from src.auth.schemas import UserSchema


class Base(DeclarativeBase):
    __abstract__ = True
    id: Mapped[int]  = mapped_column( primary_key=True)


class User(Base):
    __tablename__ = "user"

    first_name: Mapped[str] = mapped_column()
    last_name: Mapped[str] = mapped_column()
    username: Mapped[str| None] = mapped_column()
    email: Mapped[str] = mapped_column(unique=True)
    password_hash: Mapped[str] = mapped_column()

    def to_read_model(self) -> UserSchema:
        return UserSchema(
            id=self.id,
            first_name=self.first_name,
            last_name=self.last_name,
            username=self.username,
            password=self.password_hash
        )
