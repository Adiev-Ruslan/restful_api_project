import json
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from redis import Redis
from . import crud
from .models import ReferralCode
from .database import get_db
from .config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
redis_client = Redis(host=settings.redis_host, port=settings.redis_port)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = crud.get_user(db, user_id=user_id)
    if user is None:
        raise credentials_exception
    return user

# Функция для сохранения реферального кода в кэше
def cache_referral_code(referral_code: ReferralCode):
    cache_key = f"referral_code:{referral_code.owner_id}"
    redis_client.set(cache_key, json.dumps({
        "code": referral_code.code,
        "expiration_date": referral_code.expiration_date.isoformat(),
        "is_active": referral_code.is_active
    }))

# Функция для получения реферального кода из кэша
async def get_cached_referral_code(owner_id: int):
    cache_key = f"referral_code:{owner_id}"
    cached_code = await redis_client.get(cache_key)
    if cached_code:
        return json.loads(cached_code)
    return None

# Функция для удаления реферального кода из кэша
def delete_cached_referral_code(owner_id: int):
    cache_key = f"referral_code:{owner_id}"
    redis_client.delete(cache_key)



