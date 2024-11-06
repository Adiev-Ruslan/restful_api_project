from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from .database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

    # Связь с таблицей реферальных кодов
    referral_codes = relationship("ReferralCode", back_populates="owner")


class ReferralCode(Base):
    __tablename__ = "referral_codes"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expiration_date = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)

    # Связь с таблицей пользователей
    owner = relationship("User", back_populates="referral_codes")

    # Связь с рефералами, если предусмотрена таблица User для хранения списка рефералов
    referred_users = relationship("User", secondary="referrals_users", back_populates="referred_by")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.expiration_date < datetime.utcnow():
            self.is_active = False



