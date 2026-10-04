
import os, uuid, hashlib, secrets
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import create_engine, String, Integer, DateTime, Boolean, ForeignKey, Text, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from passlib.context import CryptContext

ENV=os.getenv("APP_ENV","development")
DATABASE_URL=os.getenv("DATABASE_URL","postgresql+psycopg2://chinabet:chinabet@db:5432/chinabet")
if ENV=="production" and os.getenv("SANDBOX_MODE","true").lower()!="true":
    raise RuntimeError("Este pacote exige SANDBOX_MODE=true até validação/licenciamento.")
engine=create_engine(DATABASE_URL,pool_pre_ping=True)
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False)
pwd=CryptContext(schemes=["pbkdf2_sha256"],deprecated="auto")

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__="users"
    id:Mapped[int]=mapped_column(primary_key=True)
    email:Mapped[str]=mapped_column(String(255),unique=True,index=True)
    password_hash:Mapped[str]=mapped_column(String(255))
    role:Mapped[str]=mapped_column(String(32),default="user")
    active:Mapped[bool]=mapped_column(Boolean,default=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
class SessionToken(Base):
    __tablename__="sessions"
    id:Mapped[int]=mapped_column(primary_key=True)
    token_hash:Mapped[str]=mapped_column(String(128),unique=True,index=True)
    user_id:Mapped[int]=mapped_column(ForeignKey("users.id"),index=True)
    expires_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
    revoked_at:Mapped[Optional[datetime]]=mapped_column(DateTime(timezone=True),nullable=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
    ip_address:Mapped[Optional[str]]=mapped_column(String(64),nullable=True)
class Audit(Base):
    __tablename__="audits"
    id:Mapped[int]=mapped_column(primary_key=True)
    user_id:Mapped[Optional[int]]=mapped_column(ForeignKey("users.id"),nullable=True)
    action:Mapped[str]=mapped_column(String(100),index=True)
    correlation_id:Mapped[str]=mapped_column(String(64),index=True)
    details:Mapped[Optional[str]]=mapped_column(Text,nullable=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),index=True)
Base.metadata.create_all(engine)

app=FastAPI(title="ChinaBet MVP v14",docs_url="/docs",redoc_url=None)
app.add_middleware(CORSMiddleware,
 allow_origins=os.getenv("ALLOWED_ORIGINS","http://localhost:8080").split(","),
 allow_credentials=False,allow_methods=["GET","POST","PATCH"],allow_headers=["Authorization","Content-Type","X-Correlation-ID"])

def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()
def token_hash(v): return hashlib.sha256(v.encode()).hexdigest()
def audit(db,request,action,user_id=None,details=None):
    cid=request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    db.add(Audit(user_id=user_id,action=action,correlation_id=cid,details=details));db.commit()
    return cid
def current_user(authorization:str=Header(default=""),db:Session=Depends(get_db)):
    if not authorization.startswith("Bearer "): raise HTTPException(401,"Sessão ausente")
    s=db.query(SessionToken).filter(SessionToken.token_hash==token_hash(authorization[7:])).first()
    if not s or s.revoked_at or s.expires_at<=datetime.now(timezone.utc): raise HTTPException(401,"Sessão inválida")
    u=db.get(User,s.user_id)
    if not u or not u.active: raise HTTPException(403,"Usuário inativo")
    return u
def roles(*allowed):
    def dep(u=Depends(current_user)):
        if u.role not in allowed: raise HTTPException(403,"Permissão insuficiente")
        return u
    return dep

class Register(BaseModel):
    email:str
    password:str=Field(min_length=10)
    @field_validator("email")
    @classmethod
    def email_valid(cls,v):
        v=v.strip().lower()
        if "@" not in v or len(v)>255: raise ValueError("E-mail inválido")
        return v

class Login(BaseModel):
    email:str
    password:str

@app.get("/health")
def health(db:Session=Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status":"ok","database":"ok","sandbox":True,"version":"v14"}

@app.get("/config/safety")
def safety():
    return {"environment":ENV,"sandbox_mode":os.getenv("SANDBOX_MODE","true").lower()=="true",
            "real_money_enabled":False,"real_provider_integrations":False}

@app.post("/auth/register")
def register(d:Register,request:Request,db:Session=Depends(get_db)):
    if db.query(User).filter(User.email==d.email).first(): raise HTTPException(409,"E-mail já cadastrado")
    u=User(email=d.email,password_hash=pwd.hash(d.password))
    db.add(u);db.commit();audit(db,request,"auth.register",u.id)
    return {"id":u.id,"email":u.email,"role":u.role}

@app.post("/auth/login")
def login(d:Login,request:Request,db:Session=Depends(get_db)):
    u=db.query(User).filter(User.email==d.email.lower().strip()).first()
    if not u or not pwd.verify(d.password,u.password_hash):
        audit(db,request,"auth.login_failed",None,"invalid_credentials")
        raise HTTPException(401,"Credenciais inválidas")
    if not u.active: raise HTTPException(403,"Usuário inativo")
    raw=secrets.token_urlsafe(32)
    db.add(SessionToken(token_hash=token_hash(raw),user_id=u.id,
        expires_at=datetime.now(timezone.utc)+timedelta(hours=8),
        ip_address=request.client.host if request.client else None))
    db.commit();audit(db,request,"auth.login",u.id)
    return {"access_token":raw,"token_type":"bearer","expires_in":28800}

@app.post("/auth/logout")
def logout(request:Request,authorization:str=Header(default=""),db:Session=Depends(get_db),u=Depends(current_user)):
    s=db.query(SessionToken).filter(SessionToken.token_hash==token_hash(authorization[7:])).first()
    if s: s.revoked_at=datetime.now(timezone.utc);db.commit()
    audit(db,request,"auth.logout",u.id);return {"ok":True}

@app.get("/me")
def me(u=Depends(current_user)): return {"id":u.id,"email":u.email,"role":u.role}

@app.get("/admin/security")
def security(db:Session=Depends(get_db),u=Depends(roles("admin","operator"))):
    now=datetime.now(timezone.utc)
    return {"users":db.query(User).count(),
            "active_sessions":db.query(SessionToken).filter(SessionToken.revoked_at.is_(None),SessionToken.expires_at>now).count(),
            "audit_events":db.query(Audit).count(),"sandbox":True}
