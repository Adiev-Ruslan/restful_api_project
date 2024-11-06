from fastapi import FastAPI, Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from . import models, schemas, crud, security
from .database import SessionLocal, engine, get_db
from .dependecies import get_current_user
from .config import settings
from .security import create_access_token
from jose import JWTError, jwt
from .crud import cache_referral_code, get_cached_referral_code

# Создание таблиц при запуске приложения
models.Base.metadata.create_all(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="Referral API",
    description="API для управления реферальной системой",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


# Зависимость для подключения к базе данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user


@app.post("/users/", response_model=schemas.UserResponse)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)

@app.post("/users/{user_id}/referrals/", response_model=schemas.ReferralResponse)
def create_referral(user_id: int, referral: schemas.ReferralCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Проверяем, есть ли уже активный код
    active_code = crud.get_active_referral_code(db, user_id=user_id)
    if active_code:
        raise HTTPException(status_code=400, detail="An active referral code already exists.")

    # Создаем и кешируем код
    new_code = crud.create_referral_code(db=db, referral=referral, user_id=user_id)
    cache_referral_code(user_id=user_id, code=new_code.code, expiry=referral.expiry_in_seconds)
    return new_code


@app.get("/users/{user_id}/referrals/", response_model=list[schemas.ReferralResponse])
async def get_referrals(user_id: int, db: Session = Depends(get_db),
                        current_user: models.User = Depends(get_current_user)):

    # Проверяем, что запрашивающий пользователь — это сам пользователь или администратор
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to view this user's referrals")

    # Проверяем кэш
    cached_referral_code = await get_cached_referral_code(user_id)
    if cached_referral_code:
        return cached_referral_code

    # Если кода нет в кэше, получаем его из базы данных
    referral_code = crud.get_active_referral_code(db=db, user_id=user_id)
    if not referral_code:
        raise HTTPException(status_code=404, detail="Referral code not found")

    # Сохраняем код в кэш для будущих запросов
    cache_referral_code(referral_code)
    return referral_code

# Деактивация реферального кода
@app.put("/users/{user_id}/referrals/{referral_id}/deactivate", response_model=schemas.ReferralResponse)
def deactivate_referral(user_id: int, referral_id: int, db: Session = Depends(get_db)):
    referral = crud.get_referral_by_id(db, referral_id=referral_id)
    if not referral or referral.owner_id != user_id:
        raise  HTTPException(status_code=404, detail="Referral code not found or unauthorized.")

    return crud.deactivate_referral_code(db, code_id=referral_id)

# Функция для аутентификации пользователя
def authenticate_user(db: Session, email: str, password: str):
    user = crud.get_user_by_email(db, email=email)
    if not user:
        return False
    if not security.verify_password(password, user.hashed_password):
        return False
    return user

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password"
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.delete("/users/{user_id}/referrals/", status_code=204)
async def delete_referral_code(
        user_id: int, db: Session = Depends(get_db),
        token: str = Depends(oauth2_scheme)):
    current_user = crud.get_current_user_from_token(db, token, user_id)
    if not current_user:
        raise HTTPException(status_code=403, detail="Not authorized")

    crud.delete_referral_code(db, user_id=user_id)
    return None

@app.get("/referrals/{referral_id}", response_model=schemas.ReferralResponse)
def read_referral(referral_id: int, db: Session = Depends(get_db)):
    referral = crud.get_referral_by_id(db, referral_id=referral_id)
    if referral is None:
        raise HTTPException(status_code=404, detail="Referral not found")
    return referral

@app.get("/referral_code/", response_model=schemas.ReferralResponse)
async def get_referral_code_by_email(email: str, db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, email=email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    referral_code = crud.get_active_referral_code(db, user_id=user.id)
    if not referral_code:
        raise HTTPException(status_code=404, detail="No active referral code found for this user")

    return referral_code

@app.post("/register_with_referral/", response_model=schemas.UserResponse)
async def register_with_referral(
        user: schemas.UserCreate, referral_code: str,
        db: Session = Depends(get_db)):

    # Проверяем, что реферальный код существует и активен
    referrer = crud.get_user_by_referral_code(db, referral_code=referral_code)
    if not referrer:
        raise  HTTPException(status_code=404, detail="Invalid or expired referral code")

    # Создаем нового пользователя, используя стандартную функцию create_user
    new_user = crud.create_user(db=db, user=user)

    # Добавляем нового пользователя в список рефералов referrer
    crud.add_referral_to_user(db, referrer_id=referrer.id, referrer_user_if=new_user.id)
