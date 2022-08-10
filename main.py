from datetime import timedelta, datetime
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status
import os

from jwt import PyJWTError
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from pydantic import BaseModel
from pydantic import EmailStr
from passlib.context import CryptContext
import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from starlette.status import HTTP_401_UNAUTHORIZED

SQLALCHEMY_DATABASE_URL = os.environ['SQLALCHEMY_DATABASE_URL']
engine = create_engine(
    SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
ACCESS_TOKEN_EXPIRE_MINUTES = 60
ALGORITHM = "HS256"
SECRET_KEY = "78214125432A462D4A614E645267556B58703273357638792F423F4528472B4B"


@app.get("/")
async def root():
    return {"message": "TODO API"}


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    last_name = Column(String)
    first_name = Column(String)
    email = Column(String, unique=True, index=True)
    todos = relationship("TODO", back_populates="owner", cascade="all, delete-orphan")


class TODO(Base):
    __tablename__ = "todos"
    id = Column(Integer, primary_key=True, index=True)
    text = Column(String, index=True)
    completed = Column(Boolean, default=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="todos")


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    last_name: str
    first_name: str
    password: str


class TODOCreate(BaseModel):
    text: str
    completed: bool


class TODOUpdate(TODOCreate):
    id: int


def get_user_by_email(db: Session, email: str):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with email {email} not found",
        )
    return user


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


def get_current_user(db: Session = Depends(get_db),
                     token: str = Depends(oauth2_scheme)):
    return decode_access_token(db, token)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(db, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(*, data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(db, token):
    credentials_exception = HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("email")
        if email is None:
            raise credentials_exception
    except PyJWTError:
        raise credentials_exception
    user = get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user


def create_todo(db: Session, current_user: User, todo_data: TODOCreate):
    todo = TODO(text=todo_data.text,
                completed=todo_data.completed)
    todo.owner = current_user
    db.add(todo)
    db.commit()
    db.refresh(todo)
    return todo


def update_todo(db: Session, todo_data: TODOUpdate):
    todo = db.query(TODO).filter(TODO.id == id).first()
    todo.text = todo_data.text
    todo.completed = todo.completed
    db.commit()
    db.refresh(todo)
    return todo


def delete_todo(db: Session, id: int):
    todo = db.query(TODO).filter(TODO.id == id).first()
    db.delete(todo)
    db.commit()


def get_user_todos(db: Session, userid: int):
    return db.query(TODO).filter(TODO.owner_id == userid).all()


def create_user(db: Session, request: UserCreate):
    new_user = User(
        first_name=request.first_name,
        last_name=request.last_name,
        email=request.email)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.get("/api/me", response_model=User)
def read_logged_in_user(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/api/users", response_model=User)
def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    user = get_user_by_email(db, user_data.email)
    if user:
        raise HTTPException(status_code=409,
                            detail="Email already registered.")
    signedup_user = create_user(db, user_data)
    return signedup_user


@app.post("/api/token")
def login_for_access_token(db: Session = Depends(get_db),
                           form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email},
                                       expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/mytodos", response_model=List[TODO])
def get_own_todos(current_user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    todos = get_user_todos(db, current_user.id)
    return todos


@app.post("/api/todos", response_model=TODO)
def add_a_todo(todo_data: TODOCreate,
               current_user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    todo = create_todo(db, current_user, todo_data)
    return todo


@app.put("/api/todos/{todo_id}", response_model=TODO)
def update_a_todo(todo_id: int,
                  todo_data: TODOUpdate,
                  current_user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    todo = get_user_todos(db, todo_id)
    updated_todo = update_todo(db, todo_id, todo_data)
    return updated_todo


@app.delete("/api/todos/{todo_id}")
def delete_a_meal(todo_id: int,
                  current_user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    delete_todo(db, todo_id)
    return {"detail": "TODO Deleted"}
