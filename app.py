from __future__ import annotations

import base64
import binascii
import ctypes
import hmac
import os
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Iterator
from urllib.parse import urlsplit

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, field_validator

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(
    os.environ.get("VAULTPASS_DB_PATH", str(BASE_DIR / "vaultpass.sqlite3"))
).expanduser()
SESSION_COOKIE = "vaultpass_session"
SESSION_TTL_SECONDS = 30 * 60
CHALLENGE_TTL_SECONDS = 120
VERIFIER_PROTECTION_KEY = "verifier_protection"
VERIFIER_PROTECTION_FORMAT = b"windows-dpapi-v1"
sessions: dict[str, "VaultSession"] = {}
sessions_lock = threading.Lock()
login_challenges: dict[str, tuple[bytes, float]] = {}
challenges_lock = threading.Lock()


@dataclass
class VaultSession:
    csrf_token: str
    expires_at: float


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint32),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _protect_verifier(verifier: bytes, *, unprotect: bool = False) -> bytes:
    if os.name != "nt":
        raise RuntimeError("Master-password verifier protection requires Windows DPAPI.")

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    input_buffer = ctypes.create_string_buffer(verifier)
    input_blob = _DataBlob(
        len(verifier),
        ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    output_blob = _DataBlob()
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    if unprotect:
        transform = crypt32.CryptUnprotectData
        transform.argtypes = [
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(_DataBlob),
        ]
        transform.restype = ctypes.c_int
        succeeded = transform(
            ctypes.byref(input_blob),
            None,
            None,
            None,
            None,
            flags,
            ctypes.byref(output_blob),
        )
    else:
        transform = crypt32.CryptProtectData
        transform.argtypes = [
            ctypes.POINTER(_DataBlob),
            ctypes.c_wchar_p,
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(_DataBlob),
        ]
        transform.restype = ctypes.c_int
        succeeded = transform(
            ctypes.byref(input_blob),
            None,
            None,
            None,
            None,
            flags,
            ctypes.byref(output_blob),
        )
    if not succeeded:
        raise OSError(ctypes.get_last_error(), "Windows DPAPI could not protect the verifier.")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree(output_blob.pbData)


def decode_fixed_base64(value: str, expected_bytes: int, field_name: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{field_name} must be valid base64.") from None
    if len(decoded) != expected_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{field_name} has an invalid length.")
    return decoded


class SetupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    salt: str = Field(min_length=24, max_length=24)
    verifier: str = Field(min_length=44, max_length=44)

    @field_validator("salt")
    @classmethod
    def validate_salt(cls, value: str) -> str:
        decode_fixed_base64(value, 16, "Salt")
        return value

    @field_validator("verifier")
    @classmethod
    def validate_verifier(cls, value: str) -> str:
        decode_fixed_base64(value, 32, "Verifier")
        return value


class UnlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=32, max_length=32)
    proof: str = Field(min_length=44, max_length=44)

    @field_validator("challenge_id")
    @classmethod
    def validate_challenge_id(cls, value: str) -> str:
        if not value.isascii() or not all(
            character.isalnum() or character in "-_" for character in value
        ):
            raise ValueError("Challenge identifier is invalid.")
        return value

    @field_validator("proof")
    @classmethod
    def validate_proof(cls, value: str) -> str:
        decode_fixed_base64(value, 32, "Proof")
        return value


class CredentialCiphertext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    encrypted_data: str = Field(min_length=40, max_length=16_000)

    @field_validator("encrypted_data")
    @classmethod
    def validate_ciphertext(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("Encrypted data must be valid base64.") from None
        if len(decoded) < 28 or base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("Encrypted data is incomplete or invalid.")
        return value


def connect_database() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def database_connection() -> Iterator[sqlite3.Connection]:
    connection = connect_database()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    with database_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )
            """
        )
        verifier = connection.execute(
            "SELECT value FROM settings WHERE key = 'verifier'"
        ).fetchone()
        protection = connection.execute(
            "SELECT value FROM settings WHERE key = ?",
            (VERIFIER_PROTECTION_KEY,),
        ).fetchone()
        if verifier and not protection:
            protected_verifier = _protect_verifier(bytes(verifier["value"]))
            connection.execute(
                "UPDATE settings SET value = ? WHERE key = 'verifier'",
                (protected_verifier,),
            )
            connection.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                (VERIFIER_PROTECTION_KEY, VERIFIER_PROTECTION_FORMAT),
            )
        elif protection and bytes(protection["value"]) != VERIFIER_PROTECTION_FORMAT:
            raise RuntimeError("Unsupported master-password verifier protection format.")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )


initialize_database()

app = FastAPI(
    title="VaultPass",
    description="A local, single-user password vault.",
    version="1.0.0",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    csp = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    if request.url.path.startswith("/docs") or request.url.path.startswith("/redoc"):
        csp = csp.replace(
            "script-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        ).replace(
            "style-src 'self'",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        )
    response.headers["Content-Security-Policy"] = csp
    if request.url.path.startswith("/api/") or request.url.path == "/":
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(RequestValidationError)
async def sanitized_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    errors = [
        {
            "field": ".".join(str(part) for part in error["loc"]),
            "message": error["msg"],
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={"detail": "Request validation failed.", "errors": errors},
    )


def is_configured() -> bool:
    with database_connection() as connection:
        return (
            connection.execute(
                "SELECT 1 FROM settings WHERE key IN ('salt', 'verifier') "
                "GROUP BY 1 HAVING COUNT(*) = 2"
            ).fetchone()
            is not None
        )


def load_salt_and_verifier() -> tuple[bytes, bytes]:
    with database_connection() as connection:
        rows = connection.execute(
            "SELECT key, value FROM settings WHERE key IN ('salt', 'verifier', ?)",
            (VERIFIER_PROTECTION_KEY,),
        ).fetchall()
    values = {row["key"]: bytes(row["value"]) for row in rows}
    if "salt" not in values or "verifier" not in values:
        raise HTTPException(status_code=500, detail="Vault configuration is incomplete.")
    if values.get(VERIFIER_PROTECTION_KEY) != VERIFIER_PROTECTION_FORMAT:
        raise HTTPException(status_code=500, detail="Vault verifier protection is unavailable.")
    try:
        verifier = _protect_verifier(values["verifier"], unprotect=True)
    except OSError:
        raise HTTPException(
            status_code=500,
            detail="Vault verifier cannot be opened by this Windows account.",
        ) from None
    return values["salt"], verifier


def secure_cookies_enabled() -> bool:
    secure_setting = os.environ.get("VAULTPASS_SECURE_COOKIES", "").lower()
    if secure_setting:
        return secure_setting in {"1", "true", "yes"}
    environment = os.environ.get("VAULTPASS_ENV", os.environ.get("ENVIRONMENT", "local"))
    return environment.lower() in {"production", "prod"}


def create_session(response: Response) -> dict[str, str]:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with sessions_lock:
        expired = [key for key, value in sessions.items() if value.expires_at <= now]
        for key in expired:
            del sessions[key]
        sessions[token] = VaultSession(
            csrf_token=csrf_token,
            expires_at=now + SESSION_TTL_SECONDS,
        )
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=secure_cookies_enabled(),
        samesite="strict",
        path="/",
    )
    return {"csrf_token": csrf_token}


def create_login_challenge() -> tuple[str, bytes]:
    now = time.monotonic()
    with challenges_lock:
        expired = [key for key, (_, expiry) in login_challenges.items() if expiry <= now]
        for key in expired:
            del login_challenges[key]
        if len(login_challenges) >= 1024:
            raise HTTPException(
                status_code=503, detail="Too many unlock attempts. Please retry shortly."
            )
        challenge_id = secrets.token_urlsafe(24)
        nonce = secrets.token_bytes(32)
        login_challenges[challenge_id] = (nonce, now + CHALLENGE_TTL_SECONDS)
    return challenge_id, nonce


def consume_login_challenge(challenge_id: str) -> bytes:
    with challenges_lock:
        challenge = login_challenges.pop(challenge_id, None)
    if challenge is None or challenge[1] <= time.monotonic():
        raise HTTPException(status_code=401, detail="Unlock challenge expired. Try again.")
    return challenge[0]


def get_session(
    vaultpass_session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> VaultSession:
    if not vaultpass_session:
        raise HTTPException(status_code=401, detail="Unlock the vault to continue.")
    now = time.monotonic()
    with sessions_lock:
        session = sessions.get(vaultpass_session)
        if session and session.expires_at > now:
            return session
        sessions.pop(vaultpass_session, None)
    raise HTTPException(status_code=401, detail="Your session expired. Unlock the vault again.")


def require_csrf(request: Request, session: VaultSession) -> None:
    supplied = request.headers.get("x-vault-csrf", "")
    if not supplied or not hmac.compare_digest(supplied, session.csrf_token):
        raise HTTPException(status_code=403, detail="Security token missing or invalid.")


def check_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        return
    parsed_origin = urlsplit(origin)
    host = request.headers.get("host", "")
    if (
        parsed_origin.scheme != request.url.scheme
        or parsed_origin.netloc.lower() != host.lower()
    ):
        raise HTTPException(status_code=403, detail="Cross-origin request rejected.")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def decode_ciphertext(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


@app.get("/", include_in_schema=False)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"configured": is_configured()},
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/auth/status")
async def auth_status():
    if not is_configured():
        return {"configured": False}
    salt, _ = load_salt_and_verifier()
    return {"configured": True, "salt": base64.b64encode(salt).decode("ascii")}


@app.get("/api/auth/challenge")
async def auth_challenge():
    if not is_configured():
        raise HTTPException(status_code=409, detail="Set up your vault first.")
    challenge_id, nonce = create_login_challenge()
    return {
        "challenge_id": challenge_id,
        "challenge": base64.b64encode(nonce).decode("ascii"),
    }


@app.post("/api/auth/setup")
async def setup_vault(
    payload: SetupRequest, request: Request, response: Response
) -> dict[str, str]:
    check_same_origin(request)
    salt = decode_fixed_base64(payload.salt, 16, "Salt")
    verifier = decode_fixed_base64(payload.verifier, 32, "Verifier")
    try:
        with database_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM settings WHERE key = 'salt'"
            ).fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="Vault is already set up. Unlock it instead.",
                )
            connection.executemany(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                [
                    ("salt", salt),
                    ("verifier", _protect_verifier(verifier)),
                    (VERIFIER_PROTECTION_KEY, VERIFIER_PROTECTION_FORMAT),
                ],
            )
    except sqlite3.Error:
        raise HTTPException(
            status_code=500, detail="Vault setup failed. Check local database access."
        ) from None
    result = create_session(response)
    result["message"] = "Your encrypted vault is ready."
    return result


@app.post("/api/auth/unlock")
async def unlock_vault(
    payload: UnlockRequest, request: Request, response: Response
) -> dict[str, str]:
    check_same_origin(request)
    if not is_configured():
        raise HTTPException(status_code=409, detail="Set up your vault first.")
    nonce = consume_login_challenge(payload.challenge_id)
    _, stored_verifier = load_salt_and_verifier()
    proof = decode_fixed_base64(payload.proof, 32, "Proof")
    expected_proof = hmac.new(
        stored_verifier,
        nonce + payload.challenge_id.encode("ascii"),
        "sha256",
    ).digest()
    if not hmac.compare_digest(proof, expected_proof):
        raise HTTPException(status_code=401, detail="Incorrect master password.")
    result = create_session(response)
    result["message"] = "Vault unlocked."
    return result


@app.post("/api/auth/lock")
async def lock_vault(
    request: Request,
    response: Response,
    session: Annotated[VaultSession, Depends(get_session)],
    vaultpass_session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> dict[str, str]:
    check_same_origin(request)
    require_csrf(request, session)
    if vaultpass_session:
        with sessions_lock:
            sessions.pop(vaultpass_session, None)
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=secure_cookies_enabled(),
        samesite="strict",
    )
    return {"message": "Vault locked."}


@app.get("/api/credentials")
async def list_credentials(
    session: Annotated[VaultSession, Depends(get_session)],
) -> dict[str, list[dict]]:
    with database_connection() as connection:
        rows = connection.execute(
            "SELECT id, encrypted_data, created_at, updated_at "
            "FROM credentials ORDER BY updated_at DESC"
        ).fetchall()
    return {
        "credentials": [
            {
                "id": row["id"],
                "encrypted_data": base64.b64encode(
                    bytes(row["encrypted_data"])
                ).decode("ascii"),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]
    }


@app.post("/api/credentials", status_code=201)
async def add_credential(
    payload: CredentialCiphertext,
    request: Request,
    session: Annotated[VaultSession, Depends(get_session)],
) -> dict[str, str]:
    check_same_origin(request)
    require_csrf(request, session)
    credential_id = str(payload.id)
    now = utc_now()
    with database_connection() as connection:
        try:
            connection.execute(
                "INSERT INTO credentials (id, encrypted_data, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (credential_id, decode_ciphertext(payload.encrypted_data), now, now),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=409, detail="Credential identifier already exists."
            ) from None
    return {
        "id": credential_id,
        "created_at": now,
        "updated_at": now,
        "message": "Credential saved.",
    }


@app.put("/api/credentials/{credential_id}")
async def update_credential(
    credential_id: uuid.UUID,
    payload: CredentialCiphertext,
    request: Request,
    session: Annotated[VaultSession, Depends(get_session)],
) -> dict[str, str]:
    check_same_origin(request)
    require_csrf(request, session)
    normalized_id = str(credential_id)
    if payload.id != credential_id:
        raise HTTPException(status_code=400, detail="Credential identifier mismatch.")
    now = utc_now()
    with database_connection() as connection:
        cursor = connection.execute(
            "UPDATE credentials SET encrypted_data = ?, updated_at = ? WHERE id = ?",
            (decode_ciphertext(payload.encrypted_data), now, normalized_id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Credential not found.")
    return {
        "id": normalized_id,
        "updated_at": now,
        "message": "Credential updated.",
    }


@app.delete("/api/credentials/{credential_id}")
async def delete_credential(
    credential_id: uuid.UUID,
    request: Request,
    session: Annotated[VaultSession, Depends(get_session)],
) -> dict[str, str]:
    check_same_origin(request)
    require_csrf(request, session)
    with database_connection() as connection:
        cursor = connection.execute(
            "DELETE FROM credentials WHERE id = ?", (str(credential_id),)
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Credential not found.")
    return {"message": "Credential deleted."}
