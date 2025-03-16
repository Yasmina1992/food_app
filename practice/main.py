from fastapi import FastAPI, status, HTTPException, Depends
import models
from database import engine, SessionLocal
from sqlalchemy.orm import Session
from typing import Annotated
import auth

app = FastAPI()
app.include_router(auth.router)

models.Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]

@app.get("/", status_code=status.HTTP_200_OK)
async def user(db: db_dependency):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Athentication Failed")
    return {"User": user}
