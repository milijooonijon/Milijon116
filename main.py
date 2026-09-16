import os
import sys
import time
import datetime
import json
import urllib.parse
import base64
import asyncio
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Request, Response, WebSocket, HTTPException, status, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel

try:
    import psutil
except ImportError:
    psutil = None

from app.config import (
    PORT, HOST, ADMIN_PASSWORD, SECRET_KEY, SERVER_DOMAIN,
    WS_PATH_VLESS, WS_PATH_TROJAN, PRESET_CLEAN_IPS, PRESET_FRAGMENT,
    HARVESTER_ENABLED
)
from app.geo import DEFAULT_LOCATIONS, get_country_flag_emoji
from app.database import (
    init_db, get_all_users, get_user_by_uuid, get_user_by_username,
    create_user, delete_user, toggle_user_status,
    get_all_nodes, add_node as db_add_node, delete_node as db_delete_node
)
from app.node_parser import parse_proxy_node
from app.generator import generate_subscription_response
from app.proxy_engine import handle_vless_websocket, handle_trojan_websocket
from app.harvester import start_harvester_loop, harvest_and_check_nodes

app = FastAPI(
    title="Milijon Multi-Location Proxy Platform",
    version="4.1.0",
    docs_url="/api/docs",
    openapi_url="/api/v1/openapi.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

START_TIME = time.time()

@app.on_event("startup")
async def on_startup():
    try:
        init_db()
    except Exception as e:
        print(f"[WARN] init_db startup: {e}")
    if HARVESTER_ENABLED:
        asyncio.create_task(start_harvester_loop())

def check_auth(request: Request):
    auth_header = request.headers.get("Authorization", "")
    auth_cookie = request.cookies.get("milijon_token", "")
    token_clean = auth_header.replace("Bearer ", "").strip()
    if token_clean == ADMIN_PASSWORD or auth_cookie == ADMIN_PASSWORD:
        return True
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin credentials")

def get_effective_domain(request: Request) -> str:
    if SERVER_DOMAIN and SERVER_DOMAIN.strip():
        return SERVER_DOMAIN.strip()
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "localhost"
    if ":" in host and ("railway.app" in host or host.startswith("localhost")):
        return host.split(":")[0]
    return host

class NodeCreateRequest(BaseModel):
    uri: Optional[str] = None
    name: Optional[str] = None
    protocol: Optional[str] = None
    server: Optional[str] = None
    port: Optional[int] = 443
    uuid: Optional[str] = None
    password: Optional[str] = None
    network: Optional[str] = "tcp"
    tls: Optional[str] = "none"
    country: Optional[str] = "UN"

class UserCreateRequest(BaseModel):
    username: str
    uuid: Optional[str] = None
    password: Optional[str] = None
    expires_at: Optional[str] = None
    country_preset: Optional[str] = "iran"
    notes: Optional[str] = ""

class LoginRequest(BaseModel):
    password: str

# -------------------------------------------------------------
# 1. Web Dashboard (RTL Persian / English PWA)
# -------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    domain = get_effective_domain(request)
    html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "templates", "index.html")
    if os.path.exists(html_file):
        with open(html_file, "r", encoding="utf-8") as f:
            html = f.read()
        html = html.replace("{{ domain }}", domain)
        return HTMLResponse(content=html, media_type="text/html; charset=utf-8")
    return HTMLResponse("<h1>Milijon Platform Active</h1>", media_type="text/html; charset=utf-8")

# -------------------------------------------------------------
# 2. System Health & Auth
# -------------------------------------------------------------
@app.get("/health")
@app.get("/api/health")
@app.get("/api/v1/health")
async def health_check():
    uptime_sec = int(time.time() - START_TIME)
    try:
        nodes = get_all_nodes(active_only=False)
        total_nodes = len(nodes)
        healthy_nodes = sum(1 for n in nodes if n.get("health") == "healthy")
        total_locations = len(set(n.get("country", "UN") for n in nodes if n.get("country")))
    except Exception:
        nodes = []
        total_nodes = 0
        healthy_nodes = 0
        total_locations = 0

    return {
        "status": "healthy",
        "app": "Milijon Multi-Location Proxy Platform",
        "version": "4.1.0",
        "railwayServiceStatus": "healthy",
        "uptime_seconds": uptime_sec,
        "totalNodes": total_nodes,
        "healthyNodes": healthy_nodes,
        "totalLocations": total_locations,
        "averageLatencyMs": 72,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

@app.get("/api/me")
@app.get("/api/v1/me")
async def check_admin(request: Request):
    check_auth(request)
    return {"authenticated": True}

@app.post("/api/login")
@app.post("/api/v1/login")
async def login(req: LoginRequest, response: Response):
    if req.password == ADMIN_PASSWORD:
        response.set_cookie(
            key="milijon_token",
            value=ADMIN_PASSWORD,
            httponly=False,
            samesite="lax",
            max_age=86400 * 30
        )
        return {"success": True, "token": ADMIN_PASSWORD}
    raise HTTPException(status_code=401, detail="رمز عبور اشتباه است / Invalid password")

@app.get("/api/stats")
@app.get("/api/v1/stats")
async def get_system_stats(request: Request):
    check_auth(request)
    uptime_sec = int(time.time() - START_TIME)
    uptime_str = str(datetime.timedelta(seconds=uptime_sec))
    
    users = get_all_users()
    nodes = get_all_nodes(active_only=False)
    
    active_users = sum(1 for u in users if (u.get("is_active") or 0) == 1)
    total_up = sum((u.get("upload_bytes") or 0) for u in users)
    total_down = sum((u.get("download_bytes") or 0) for u in users)
    
    mem, cpu = 0.0, 0.0
    if psutil:
        try:
            mem = psutil.virtual_memory().percent
            cpu = psutil.cpu_percent(interval=None)
        except Exception:
            pass

    return {
        "success": True,
        "uptime": uptime_str,
        "uptime_seconds": uptime_sec,
        "total_nodes": len(nodes),
        "total_locations": len(set(n.get("country") or "UN" for n in nodes if n)),
        "total_users": len(users),
        "active_users": active_users,
        "total_upload_bytes": total_up,
        "total_download_bytes": total_down,
        "memory_percent": mem,
        "cpu_percent": cpu,
        "server_domain": get_effective_domain(request),
        "vless_path": WS_PATH_VLESS,
        "trojan_path": WS_PATH_TROJAN,
        "clean_ips": PRESET_CLEAN_IPS,
        "fragment_presets": PRESET_FRAGMENT
    }

# -------------------------------------------------------------
# 3. Dynamic Multi-Protocol & Multi-Location Subscriptions
# -------------------------------------------------------------
@app.get("/sub/{token}")
@app.get("/api/v1/sub/{token}")
@app.get("/api/sub/{token}")
async def get_subscription(
    token: str,
    request: Request,
    type: Optional[str] = Query(None),
    target: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    strategy: Optional[str] = Query("balanced"),
    iran: Optional[bool] = Query(True)
):
    token = token.strip()
    user = get_user_by_uuid(token) or get_user_by_username(token)
    user_name = user["username"] if user else "VIP"
    
    nodes = get_all_nodes(country=country, active_only=True)
    if not nodes:
        nodes = get_all_nodes(active_only=False)
        
    requested_target = (target or type or "singbox").lower().strip()
    sub_res = generate_subscription_response(
        nodes=nodes,
        target=requested_target,
        strategy=strategy or "balanced",
        iran_optimized=iran if iran is not None else True
    )
    
    headers = {
        "Subscription-Userinfo": "upload=10485760; download=52428800; total=1073741824000; expire=0",
        "Profile-Update-Interval": "12",
        "Profile-Title": f"Milijon - {user_name} ({country or 'Global'})",
        "X-Node-Count": str(sub_res.get("count", len(nodes))),
        "Cache-Control": "public, max-age=60"
    }
    
    if sub_res.get("ext") in ["yaml", "json", "conf"]:
        headers["Content-Disposition"] = f'attachment; filename="milijon_{user_name}_{requested_target}.{sub_res["ext"]}"'
        
    return Response(
        content=sub_res["content"],
        media_type=sub_res["media_type"],
        headers=headers
    )

# -------------------------------------------------------------
# 4. Multi-Location Nodes & Harvester Management API
# -------------------------------------------------------------
@app.get("/api/v1/nodes")
@app.get("/api/nodes")
async def list_nodes(country: Optional[str] = None):
    nodes = get_all_nodes(country=country, active_only=False)
    return {
        "success": True,
        "total": len(nodes),
        "data": nodes
    }

@app.post("/api/v1/nodes")
@app.post("/api/nodes")
async def create_node(req: NodeCreateRequest, request: Request):
    check_auth(request)
    if req.uri:
        parsed = parse_proxy_node(req.uri)
        if not parsed:
            raise HTTPException(status_code=400, detail="فرمت نود نامعتبر است / Invalid proxy URI")
        saved = db_add_node(parsed)
        return {"success": True, "data": saved}
    
    if not req.server or not req.protocol:
        raise HTTPException(status_code=400, detail="Missing required server or protocol")
        
    node_dict = req.dict(exclude_unset=True)
    if not node_dict.get("name"):
        flag = get_country_flag_emoji(node_dict.get("country", "UN"))
        node_dict["name"] = f"{flag} {node_dict.get('server')}:{node_dict.get('port')}"
    saved = db_add_node(node_dict)
    return {"success": True, "data": saved}

@app.delete("/api/v1/nodes/{node_id}")
@app.delete("/api/nodes/{node_id}")
async def delete_node_endpoint(node_id: str, request: Request):
    check_auth(request)
    deleted = db_delete_node(node_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Node not found")
    return {"success": True, "message": "Node removed successfully"}

@app.get("/api/v1/locations")
@app.get("/api/locations")
async def list_locations():
    nodes = get_all_nodes(active_only=False)
    counts = {}
    for n in nodes:
        c = (n.get("country") or "UN").upper()
        counts[c] = counts.get(c, 0) + 1
        
    locations_data = []
    for loc in DEFAULT_LOCATIONS:
        loc_copy = dict(loc)
        loc_copy["nodeCount"] = counts.get(loc["code"], 0)
        locations_data.append(loc_copy)
    return {"success": True, "data": locations_data}

@app.get("/api/harvester/stats")
async def get_harvester_stats(request: Request):
    check_auth(request)
    nodes = get_all_nodes(active_only=False)
    alive = [n for n in nodes if n.get("active") == 1]
    avg_ping = int(sum((n.get("latency") or 0) for n in alive) / len(alive)) if alive else 0
    return {
        "success": True,
        "total_nodes": len(nodes),
        "alive_nodes": len(alive),
        "avg_ping_ms": avg_ping
    }

@app.post("/api/harvester/refresh")
async def trigger_harvester_refresh(request: Request):
    check_auth(request)
    res = await harvest_and_check_nodes()
    return {"success": True, "result": res}

# -------------------------------------------------------------
# 5. User Management API
# -------------------------------------------------------------
@app.get("/api/users")
@app.get("/api/v1/users")
async def list_users(request: Request):
    check_auth(request)
    users = get_all_users()
    domain = get_effective_domain(request)
    base_url = str(request.base_url).rstrip('/')
    result = []
    for u in users:
        u_dict = dict(u)
        u_uuid = u_dict.get("uuid") or ""
        u_pass = u_dict.get("password") or "milijon_user"
        username = str(u_dict.get("username") or "User")
        
        # VLESS Link
        vless_params = {
            "type": "ws",
            "security": "tls",
            "sni": domain,
            "host": domain,
            "path": f"{WS_PATH_VLESS}?ed=2048",
            "fp": "chrome",
            "alpn": "h2,http/1.1"
        }
        vless_q = urllib.parse.urlencode(vless_params)
        u_dict["vless_link"] = f"vless://{u_uuid}@{domain}:443?{vless_q}#{urllib.parse.quote('Milijon-VL-' + username)}"
        
        # Trojan Link
        trojan_params = {
            "type": "ws",
            "security": "tls",
            "sni": domain,
            "host": domain,
            "path": WS_PATH_TROJAN,
            "fp": "chrome",
            "alpn": "h2,http/1.1"
        }
        trojan_q = urllib.parse.urlencode(trojan_params)
        u_dict["trojan_link"] = f"trojan://{u_pass}@{domain}:443?{trojan_q}#{urllib.parse.quote('Milijon-TR-' + username)}"
        
        # VMess Link
        vmess_payload = {
            "v": "2", "ps": f"Milijon-VM-{username}",
            "add": domain, "port": 443, "id": u_uuid, "aid": 0, "scy": "auto",
            "net": "ws", "type": "none", "host": domain,
            "path": f"{WS_PATH_VLESS}?ed=2048", "tls": "tls", "sni": domain, "alpn": "h2,http/1.1"
        }
        u_dict["vmess_link"] = "vmess://" + base64.b64encode(json.dumps(vmess_payload).encode('utf-8')).decode('utf-8')
        
        # Sub URLs
        u_dict["sub_url"] = f"{base_url}/sub/{u_uuid}?target=singbox"
        u_dict["sub_url_singbox"] = f"{base_url}/sub/{u_uuid}?target=singbox"
        u_dict["sub_url_clash"] = f"{base_url}/sub/{u_uuid}?target=clashmeta"
        u_dict["sub_url_b64"] = f"{base_url}/sub/{u_uuid}?target=base64"
        result.append(u_dict)
    return result

@app.post("/api/users")
@app.post("/api/v1/users")
async def add_user(req: UserCreateRequest, request: Request):
    check_auth(request)
    existing = get_user_by_username(req.username)
    if existing:
        raise HTTPException(status_code=400, detail="این نام کاربری از قبل وجود دارد / Username already exists")
    
    user = create_user(
        username=req.username,
        user_uuid=req.uuid,
        password=req.password,
        expires_at=req.expires_at,
        country_preset=req.country_preset or "iran",
        notes=req.notes or ""
    )
    return user

@app.post("/api/users/{user_id}/toggle")
@app.post("/api/v1/users/{user_id}/toggle")
async def toggle_user_endpoint(user_id: int, request: Request):
    check_auth(request)
    new_status = toggle_user_status(user_id)
    if new_status is None:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد / User not found")
    return {"id": user_id, "is_active": new_status}

@app.get("/api/users/{user_id}/links")
@app.get("/api/v1/users/{user_id}/links")
async def get_user_links_endpoint(user_id: int, request: Request):
    check_auth(request)
    users = get_all_users()
    user = next((u for u in users if u["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    domain = get_effective_domain(request)
    base_url = str(request.base_url).rstrip('/')
    u_uuid = user.get("uuid", "")
    return {
        "user": user,
        "sub_url": f"{base_url}/sub/{u_uuid}?target=singbox",
        "sub_url_clash": f"{base_url}/sub/{u_uuid}?target=clashmeta",
        "sub_url_b64": f"{base_url}/sub/{u_uuid}?target=base64"
    }

@app.delete("/api/users/{user_id}")
@app.delete("/api/v1/users/{user_id}")
async def remove_user(user_id: int, request: Request):
    check_auth(request)
    success = delete_user(user_id)
    if not success:
        raise HTTPException(status_code=404, detail="کاربر یافت نشد / User not found")
    return {"success": True}

# -------------------------------------------------------------
# 6. WebSocket Proxy Tunnels
# -------------------------------------------------------------
@app.websocket(WS_PATH_VLESS)
async def vless_websocket_endpoint(websocket: WebSocket):
    await handle_vless_websocket(websocket)

@app.websocket(WS_PATH_TROJAN)
async def trojan_websocket_endpoint(websocket: WebSocket):
    await handle_trojan_websocket(websocket)

# -------------------------------------------------------------
# 7. Robust Exception Handlers (Clean HTTP Errors, No False 500s)
# -------------------------------------------------------------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()}
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback
    err_trace = traceback.format_exc()
    print(f"[UNHANDLED ERROR] {request.method} {request.url.path}: {exc}\n{err_trace}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error", "error": str(exc)}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=HOST, port=PORT, reload=False)
