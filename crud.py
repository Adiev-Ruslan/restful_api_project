import json

import redis
from app.config import settings
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from . import models, schemas, security
from .config import settings
from datetime import datetime

redis_client = redis.StrictRedis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)


def cache_referral_code(referral_code: models.ReferralCode):
    """Кэширую код с истечением по времени"""
    cache_key = f"user:{referral_code.owner_id}:referral_code"
    redis_client.set(cache_key, json.dumps(referral_code), ex=3600)


def get_cached_referral_code(user_id: int):
    return redis_client.get(f"referral_code:{user_id}")


def delete_cached_referral_code(user_id: int):
    redis_client.delete(f"referral_code:{user_id}")


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = security.get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=user.password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_active_referral_code(db: Session, user_id: int):
    return db.query(models.ReferralCode).filter(
        models.ReferralCode.owner_id == user_id,
        models.ReferralCode.is_active == True
    ).first()


def create_referral_code(db: Session, referral: schemas.ReferralCreate, user_id: int):
    new_code = models.ReferralCode(
        code=referral.code,
        expiration_date=referral.expiration_date,
        owner_id=user_id,
        is_active=True
    )
    db.add(new_code)
    db.commit()
    db.refresh(new_code)
    return new_code


def deactivate_referral_code(db: Session, code_id: int):
    code = db.query(models.ReferralCode).filter(models.ReferralCode.id == code_id).first()
    if code:
        code.is_active = False
        db.commit()
    return code


def get_current_user_from_token(db: Session, token: str, user_id: int):
    try:
        # Декодируем токен и извлекаем payload
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        token_user_id: int = payload.get("sub")

        # Проверяем, что токен принадлежит пользователю с данным ID
        if token_user_id is None or token_user_id != user_id:
            return None

        # Ищем пользователя в базе данных
        user = db.query(models.User).filter(models.User.id == user_id).first()
        return user

    except JWTError:
        return None


def get_referral_by_id(db: Session, referral_id: int):
    return db.query(models.ReferralCode).filter(models.ReferralCode.id == referral_id).first()

def get_referrals_by_user_id(db: Session, user_id: int):
    """
    Получить все реферальные коды для указанного user_id.
    """
    return db.query(models.ReferralCode).filter(models.ReferralCode.owner_id == user_id).all()


def delete_referral_code(db: Session, user_id: int):
    db.query(models.ReferralCode).filter(
        models.ReferralCode.owner_id == user_id,
        models.ReferralCode.is_active == True
    ).delete()
    db.commit()


def add_referral_to_user(db: Session, referrer_id: int, referred_user_id: int):
    # Получаем активный реферальный код пользователя (реферера)
    referral_code = db.query(models.ReferralCode).filter(
        models.ReferralCode.owner_id == referrer_id,
        models.ReferralCode.is_active == True
    ).first()

    if not referral_code:
        raise ValueError("Active referral code not found for this referrer")

    # Связываем реферала (referred_user_id) с реферальным кодом
    referral_code.referred_users.append(referred_user_id)
    db.commit()
    db.refresh(referral_code)
    return referral_code


def get_user_by_referral_code(db: Session, code: str):
    referral_code = db.query(models.ReferralCode).filter(models.ReferralCode.code == code).first()

    if not referral_code:
        return None

    return referral_code.owner
