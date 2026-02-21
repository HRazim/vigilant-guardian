"""
Vigilant Guardian — Routes d'authentification (section 8.2).

JWT RS256, expiration 1 h, refresh tokens 7 j.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_current_user
from src.api.schemas import TokenPair, UserCreate, UserRead, UserRole
from src.config.settings import settings
from src.models.user import User
from src.models.audit import AuditLog

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _create_token(data: dict, expires_delta: timedelta) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + expires_delta
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


@router.post("/register", response_model=UserRead, status_code=201)
async def register(
    user_in: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Crée un nouvel utilisateur."""
    existing = await db.execute(select(User).where(User.email == user_in.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email déjà enregistré")

    user = User(
        email=user_in.email,
        hashed_password=pwd_context.hash(user_in.password),
        role=user_in.role.value,
    )
    db.add(user)
    await db.flush()

    # Audit log
    db.add(AuditLog(
        user_id=user.id,
        action="user_registered",
        entity_type="user",
        entity_id=user.id,
    ))
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/login", response_model=TokenPair)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Authentifie et renvoie une paire access + refresh token."""
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect",
        )

    access_token = _create_token(
        {"sub": str(user.id), "role": user.role},
        timedelta(minutes=settings.jwt_expiration_minutes),
    )
    refresh_token = _create_token(
        {"sub": str(user.id), "type": "refresh"},
        timedelta(days=settings.jwt_refresh_days),
    )

    # Audit log
    db.add(AuditLog(
        user_id=user.id,
        action="user_login",
        entity_type="user",
        entity_id=user.id,
    ))
    await db.commit()

    return TokenPair(access_token=access_token, refresh_token=refresh_token)


@router.get("/me", response_model=UserRead)
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Renvoie le profil de l'utilisateur connecté."""
    return current_user
