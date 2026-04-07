"""
Authentification JWT pour Specula.

Activé via SPECULA_AUTH_ENABLED=true dans .env
Par défaut désactivé (mode démo / dev).

Endpoints :
  POST /auth/login   → { username, password } → { access_token, token_type }
  GET  /auth/me      → infos utilisateur courant

Utilisation :
  Authorization: Bearer <token>

Variables .env :
  SPECULA_AUTH_ENABLED=true
  SPECULA_AUTH_SECRET=change-me-in-production
  SPECULA_AUTH_USERNAME=admin
  SPECULA_AUTH_PASSWORD=specula
  SPECULA_AUTH_TOKEN_EXPIRE_MINUTES=480
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

router = APIRouter(prefix="/auth", tags=["auth"])

# ─── Config ────────────────────────────────────────────────────────────────────
AUTH_ENABLED = os.getenv("SPECULA_AUTH_ENABLED", "false").strip().lower() == "true"
SECRET_KEY = os.getenv("SPECULA_AUTH_SECRET", "specula-dev-secret-change-in-prod")
ALGORITHM = "HS256"
EXPIRE_MINUTES = int(os.getenv("SPECULA_AUTH_TOKEN_EXPIRE_MINUTES", "480"))
AUTH_USERNAME = os.getenv("SPECULA_AUTH_USERNAME", "admin")
AUTH_PASSWORD = os.getenv("SPECULA_AUTH_PASSWORD", "specula")

_bearer = HTTPBearer(auto_error=False)


def _create_token(data: dict[str, Any]) -> str:
    from jose import jwt  # type: ignore

    payload = {**data, "exp": datetime.now(timezone.utc) + timedelta(minutes=EXPIRE_MINUTES)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _verify_token(token: str) -> dict[str, Any]:
    from jose import JWTError, jwt  # type: ignore

    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict[str, Any] | None:
    """
    Dépendance FastAPI.
    - Si AUTH_ENABLED=false : passe toujours (mode démo)
    - Si AUTH_ENABLED=true : vérifie le token JWT
    """
    if not AUTH_ENABLED:
        return {"sub": "anonymous", "role": "viewer"}

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token d'authentification requis",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return _verify_token(credentials.credentials)


# ─── Endpoints ─────────────────────────────────────────────────────────────────
@router.post("/login")
def login(body: dict[str, str]) -> dict[str, str]:
    """
    Authentification par username/password.
    Retourne un JWT à inclure dans le header Authorization.
    """
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()

    # Vérification simple (à remplacer par DB utilisateurs en prod)
    if username != AUTH_USERNAME or password != AUTH_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
        )

    token = _create_token({"sub": username, "role": "admin"})
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me")
def me(user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
    """Retourne les informations de l'utilisateur courant."""
    return {
        "username": user.get("sub", "anonymous"),
        "role": user.get("role", "viewer"),
        "auth_enabled": AUTH_ENABLED,
    }


@router.get("/status")
def auth_status() -> dict[str, Any]:
    """Indique si l'auth est activée (utile pour le frontend)."""
    return {"auth_enabled": AUTH_ENABLED}
