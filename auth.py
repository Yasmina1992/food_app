from datetime import datetime, timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import SessionLocal
from models import Users
from starlette import status

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

SECRET_KEY = "OhpyLLO6rdPa4uqe7p1-mZmRCVlv49yEW1bRhU9BC-M"
ALGORITHM = "HS256"

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

class CreateUserRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    create_user_model = Users(
        username=create_user_request.username, 
        hashed_password=bcrypt_context.hash(create_user_request.password))

    db.add(create_user_model)
    db.commit()
    return {"message": "User created successfully"}