from pydantic import BaseModel, EmailStr


class UserSchema(BaseModel):
    id : int
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    password: str

    class Config:
        from_attributes=True

class CreateUser(BaseModel):
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    password: str


class GetUser(BaseModel):
    id: int
    first_name: str
    last_name: str
    username: str
    email: EmailStr


class UpdateUser(BaseModel):
    first_name: str
    last_name: str
    username: str
    email: EmailStr