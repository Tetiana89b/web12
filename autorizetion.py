from datetime import date, datetime, timedelta

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt
from pydantic import BaseModel
from sqlalchemy import Column, Date, Integer, String, create_engine, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

app = FastAPI()


# Конфігурація JWT
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Параметри підключення до бази даних
DATABASE_URL = "sqlite:///./contacts.sql"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Модель контакту
class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    phone_number = Column(String)
    birthday = Column(Date)
    extra_data = Column(String, nullable=True)


# Модель для створення контакту
class ContactCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone_number: str
    birthday: date
    extra_data: str = None


# Модель для оновлення контакту
class ContactUpdate(BaseModel):
    first_name: str = None
    last_name: str = None
    email: str = None
    phone_number: str = None
    birthday: date = None
    extra_data: str = None


# Модель для відображення контакту
class ContactDisplay(ContactCreate):
    id: int


# Схема контакту для валідації даних
class ContactSchema(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone_number: str
    birthday: date
    additional_data: str = None


# Модель користувача
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    def set_password(self, password):
        self.hashed_password = bcrypt.hash(password)


# Схема користувача для реєстрації
class UserLogin(BaseModel):
    email: str
    password: str


# Схема користувача для аутентифікації
class UserAuthenticate(BaseModel):
    email: str
    password: str


# Клас для хешування та перевірки паролів
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Генерування та перевірка JWT-токенів
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")




# Функція для створення та шифрування паролю
def get_password_hash(password: str):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.hash(password)

# Функція для перевірки, чи вірний пароль


def verify_password(plain_password: str, hashed_password: str):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.verify(plain_password, hashed_password)

# Функція для аутентифікації користувача


def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    return user


def get_user_by_email(db, email: str):
    return db.query(User).filter(User.email == email).first()


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Функція для отримання поточного авторизованого користувача
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return user



# З'єднання до бази даних
@app.on_event("startup")
async def startup():
    Base.metadata.create_all(bind=engine)


@app.on_event("shutdown")
async def shutdown():
    pass


# Ендпоінт для реєстрації нового користувача
@app.post("/register/")
async def register_user(user: UserLogin):
    db = SessionLocal()
    existing_user = get_user_by_email(db, user.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return JSONResponse(status_code=status.HTTP_201_CREATED, content=db_user)


# Ендпоінт для аутентифікації користувача і отримання токена доступу
@app.post("/login/")
async def login_user(user_credentials: UserLogin):
    db = SessionLocal()
    user = authenticate_user(db, user_credentials.email,
                             user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

# Ендпоінт для генерації JWT token
@app.post("/token")
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

# Захищені ендпоінти, які доступні лише авторизованим користувачам
# Ендпоінт для створення нового контакту (тільки для авторизованих користувачів)
@app.post("/contacts/", dependencies=[Depends(get_current_user)])
async def create_contact(contact: ContactCreate):
    db = SessionLocal()
    db_contact = Contact(**contact.dict())
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact


# Ендпоінт для отримання списку всіх контактів (тільки для авторизованих користувачів)
@app.get("/contacts/", dependencies=[Depends(get_current_user)])
async def get_all_contacts():
    db = SessionLocal()
    contacts = db.query(Contact).all()
    return contacts


# Ендпоінт для отримання інформації про контакт (тільки для авторизованих користувачів)
@app.get("/contacts/{contact_id}")
async def get_contact(contact_id: int):
    db = SessionLocal()
    contact = db.query(Contact).filter(Contact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact


# Ендпоінт для оновлення існуючого контакту (тільки для авторизованих користувачів)
@app.put("/contacts/{contact_id}", dependencies=[Depends(get_current_user)])
async def update_contact(contact_id: int, contact_update: ContactUpdate):
    db = SessionLocal()
    contact = db.query(Contact).filter(Contact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    update_data = contact_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(contact, key, value)

    db.commit()
    db.refresh(contact)
    return contact


# Ендпоінт для видалення контакту (тільки для авторизованих користувачів)
@app.delete("/contacts/{contact_id}", dependencies=[Depends(get_current_user)])
async def delete_contact(contact_id: int):
    db = SessionLocal()
    contact = db.query(Contact).filter(Contact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    db.delete(contact)
    db.commit()
    return {"message": "Contact deleted successfully"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
