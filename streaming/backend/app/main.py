import os
import time
import hashlib
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext

from sqlalchemy import create_engine, String, Boolean, Integer, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET")
HLS_SECRET = os.getenv("HLS_SECRET")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8080").rstrip("/")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="auth/login")

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mobile: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI()

def db():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()

def make_token(user: User):
    payload = {
        "sub": str(user.id),
        "adm": user.is_admin,
        "exp": int(time.time()) + 60 * 60 * 24
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def get_current_user(token: str = Depends(oauth2), s: Session = Depends(db)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        uid = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(401, "invalid token")
    u = s.get(User, uid)
    if not u or not u.is_active:
        raise HTTPException(401, "inactive")
    return u

def require_admin(u: User = Depends(get_current_user)):
    if not u.is_admin:
        raise HTTPException(403, "admin only")
    return u

def sign_path(path: str, ttl_seconds: int = 120):
    expires = int(time.time()) + ttl_seconds
    raw = f"{expires}{path}{HLS_SECRET}".encode()
    md5 = hashlib.md5(raw).hexdigest()
    return md5, expires

def seed_admin(s: Session):
    mobile = "0000000000"
    pw = "admin123"
    u = s.query(User).filter(User.mobile == mobile).first()
    if not u:
        u = User(mobile=mobile, password_hash=pwd.hash(pw), is_admin=True, is_active=True)
        s.add(u)
        s.commit()

@app.on_event("startup")
def startup():
    with SessionLocal() as s:
        seed_admin(s)

@app.post("/auth/login")
def login(mobile: str, password: str, s: Session = Depends(db)):
    u = s.query(User).filter(User.mobile == mobile).first()
    if not u or not u.is_active:
        raise HTTPException(401, "bad credentials")
    if not pwd.verify(password, u.password_hash):
        raise HTTPException(401, "bad credentials")
    return {"access_token": make_token(u), "token_type": "bearer", "is_admin": u.is_admin}

@app.get("/stream/url")
def stream_url(u: User = Depends(get_current_user)):
    playlist_path = "/hls/stream.m3u8"
    md5, expires = sign_path(playlist_path, ttl_seconds=120)
    url = f"{PUBLIC_BASE_URL}{playlist_path}?md5={md5}&expires={expires}"
    return {"url": url, "expires": expires}

@app.post("/admin/users")
def create_user(mobile: str, password: str, is_admin: bool = False, s: Session = Depends(db), a: User = Depends(require_admin)):
    u = s.query(User).filter(User.mobile == mobile).first()
    if u:
        raise HTTPException(400, "exists")
    u = User(mobile=mobile, password_hash=pwd.hash(password), is_admin=is_admin, is_active=True)
    s.add(u)
    s.commit()
    return {"id": u.id, "mobile": u.mobile, "is_admin": u.is_admin}

@app.post("/admin/users/{user_id}/reset")
def reset_password(user_id: int, new_password: str, s: Session = Depends(db), a: User = Depends(require_admin)):
    u = s.get(User, user_id)
    if not u:
        raise HTTPException(404, "not found")
    u.password_hash = pwd.hash(new_password)
    s.commit()
    return {"ok": True}

@app.post("/admin/users/{user_id}/disable")
def disable_user(user_id: int, s: Session = Depends(db), a: User = Depends(require_admin)):
    u = s.get(User, user_id)
    if not u:
        raise HTTPException(404, "not found")
    u.is_active = False
    s.commit()
    return {"ok": True}
