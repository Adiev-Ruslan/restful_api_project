from pydantic_settings import BaseSettings
from typing import ClassVar

class Settings(BaseSettings):
    SECRET_KEY: str = "my_secret_key_is_gachi_muchi_52_xoxo"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRES_MINUTES: int = 30
    DATABASE_URL: ClassVar[str] = "sqlite:///./test.db"
    redis_host: str = "localhost"
    redis_port: str = "6379"

settings = Settings()