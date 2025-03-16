from datetime import datetime, timedelta, timezone
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
from fastapi.encoders import jsonable_encoder

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
    print("from create_user: ", create_user_request)
    existing_user = db.query(Users).filter(Users.username == create_user_request.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken!")
    create_user_model = Users(
        username=create_user_request.username, 
        hashed_password=bcrypt_context.hash(create_user_request.password))

    db.add(create_user_model)
    db.commit()
    return {"message": "User created successfully"}


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):

    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        print("Invalid Credentials!")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Credentials!")
    
    token = create_access_token(user.username, user.id, timedelta(minutes=20))
    return {"access_token": token, "token_type": "bearer"}


@router.get("/users", status_code=status.HTTP_200_OK)
async def get_users(db: db_dependency):
    users = db.query(Users).all()
    return jsonable_encoder([{"id": user.id, "username": user.username} for user in users]) 


def authenticate_user(username: str, password: str, db: Session):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    print("from authenticate user: ", type(user))
    return user


def create_access_token(username: str, id: int, expires_delta: timedelta):
    encode = {
        'sub': username, 
        'id': id
    }
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({"exp": expires})
    
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

