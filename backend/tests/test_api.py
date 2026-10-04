
import os
os.environ["DATABASE_URL"]="sqlite+pysqlite:///./test.db"
os.environ["SANDBOX_MODE"]="true"
from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)

def test_health():
    r=client.get("/health")
    assert r.status_code==200
    assert r.json()["sandbox"] is True

def test_safety():
    r=client.get("/config/safety")
    assert r.status_code==200
    assert r.json()["real_money_enabled"] is False

def test_register_and_duplicate():
    email="test_v14@example.local"
    r=client.post("/auth/register",json={"email":email,"password":"Password123!"})
    assert r.status_code in (200,409)
    r2=client.post("/auth/register",json={"email":email,"password":"Password123!"})
    assert r2.status_code==409

def test_login():
    email="login_v14@example.local"
    client.post("/auth/register",json={"email":email,"password":"Password123!"})
    r=client.post("/auth/login",json={"email":email,"password":"Password123!"})
    assert r.status_code==200
    assert "access_token" in r.json()
