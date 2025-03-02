import logging
from functools import lru_cache
from typing import Dict

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseSettings
from jwt.utils import base64url_decode

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Environment configuration
class Settings(BaseSettings):
    KEYCLOAK_URL: str = "http://localhost:8080"
    REALM_NAME: str = "reports-realm"
    CLIENT_ID: str = "reports-api"
    ROLE_REQUIRED: str = "prothetic_user"
    ALGORITHM: str = "RS256"


settings = Settings()

# FastAPI app instance
app = FastAPI(title="Reports API", description="Secure API with Keycloak Authentication")

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@lru_cache
def fetch_keycloak_public_keys() -> Dict[str, str]:
    """Fetch and cache public keys from Keycloak."""
    try:
        jwks_url = f"{settings.KEYCLOAK_URL}/realms/{settings.REALM_NAME}/protocol/openid-connect/certs"
        response = requests.get(jwks_url, timeout=10)
        response.raise_for_status()
        jwks = response.json()

        return {
            key["kid"]: rsa.RSAPublicNumbers(
                int.from_bytes(base64url_decode(key['e'].encode()), 'big'),
                int.from_bytes(base64url_decode(key['n'].encode()), 'big')
            ).public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            for key in jwks.get("keys", []) if key.get("use") == "sig"
        }
    except requests.RequestException as e:
        logger.error(f"Failed to fetch public keys from Keycloak: {e}")
        raise RuntimeError("Could not fetch public keys from Keycloak")


def decode_jwt(token: str) -> Dict:
    """Decode and validate a JWT token."""
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        public_keys = fetch_keycloak_public_keys()

        if not kid or kid not in public_keys:
            raise HTTPException(status_code=401, detail="Invalid token: Unknown Key ID")

        return jwt.decode(token, public_keys[kid], algorithms=[settings.ALGORITHM], audience=settings.CLIENT_ID)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


def validate_user_role(token: str = Depends(oauth2_scheme)):
    """Validate user role."""
    payload = decode_jwt(token)
    roles = payload.get("realm_access", {}).get("roles", [])
    if settings.ROLE_REQUIRED not in roles:
        raise HTTPException(status_code=403, detail="Insufficient role")


@app.get("/reports", dependencies=[Depends(validate_user_role)], summary="Get reports",
         description="Returns a sample report for authorized users.")
def get_report():
    return {"report": "This is a very important report"}
