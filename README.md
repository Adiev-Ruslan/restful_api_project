# Referral Code API

## Описание проекта
Этот проект представляет собой API для управления реферальными кодами пользователей. Он предоставляет следующие возможности:

- Регистрация и аутентификация пользователей (с использованием JWT).
- Генерация и удаление реферальных кодов.
- Получение рефералов по идентификатору реферера.
- Возможность использования реферального кода для регистрации.
- UI документация (Swagger / ReDoc).

## Стек технологий
- Python 3.8+
- FastAPI
- SQLAlchemy (SQLite)
- Pydantic
- Alembic (для миграций)
- JWT для аутентификации
- Redis (если используется кэширование)
- Pytest (для тестов)

## Требования

Перед тем как запустить проект, необходимо установить зависимости:
```bash
pip install -r requirements.txt
