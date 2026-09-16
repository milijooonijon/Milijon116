import os
import sqlite3
import datetime
import uuid
import hashlib
from typing import List, Optional, Dict, Any
from app.config import DB_PATH

ACTIVE_DB_PATH = DB_PATH

def get_db():
    global ACTIVE_DB_PATH
    try:
        conn = sqlite3.connect(ACTIVE_DB_PATH, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = DELETE;")
        return conn
    except Exception:
        ACTIVE_DB_PATH = os.path.join("/tmp", "milijon.db")
        conn = sqlite3.connect(ACTIVE_DB_PATH, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = DELETE;")
        return conn

def init_db():
    global ACTIVE_DB_PATH
    for path_candidate in [ACTIVE_DB_PATH, os.path.join("/tmp", "milijon.db")]:
        try:
            conn = sqlite3.connect(path_candidate, check_same_thread=False, timeout=30.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Users Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    uuid TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    is_active INTEGER DEFAULT 1,
                    upload_bytes INTEGER DEFAULT 0,
                    download_bytes INTEGER DEFAULT 0,
                    country_preset TEXT DEFAULT 'iran',
                    notes TEXT DEFAULT ''
                )
            """)
            
            # Managed Nodes Table (Multi-Protocol & Multi-Location)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    server TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    uuid TEXT,
                    password TEXT,
                    cipher TEXT,
                    alter_id INTEGER DEFAULT 0,
                    network TEXT DEFAULT 'tcp',
                    tls TEXT DEFAULT 'none',
                    sni TEXT,
                    host TEXT,
                    path TEXT,
                    service_name TEXT,
                    flow TEXT,
                    fingerprint TEXT DEFAULT 'chrome',
                    reality_public_key TEXT,
                    reality_short_id TEXT,
                    reality_spider_x TEXT,
                    country TEXT NOT NULL DEFAULT 'UN',
                    latency INTEGER DEFAULT 70,
                    packet_loss REAL DEFAULT 0.0,
                    uptime REAL DEFAULT 99.9,
                    health TEXT DEFAULT 'healthy',
                    score REAL DEFAULT 90.0,
                    active INTEGER DEFAULT 1,
                    raw_config_hash TEXT UNIQUE,
                    created_at TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.commit()

            # Default User
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                default_uuid = str(uuid.uuid4())
                default_pass = "milijon_user"
                p_hash = hashlib.sha224(default_pass.encode('utf-8')).hexdigest()
                now_iso = datetime.datetime.utcnow().isoformat()
                cursor.execute("""
                    INSERT INTO users (username, uuid, password, password_hash, created_at, is_active, country_preset, notes)
                    VALUES (?, ?, ?, ?, ?, 1, 'iran', 'Default VIP User')
                """, ("DefaultUser", default_uuid, default_pass, p_hash, now_iso))
                conn.commit()

            # Pre-seed Multi-Location Curated Nodes
            cursor.execute("SELECT COUNT(*) FROM nodes")
            if cursor.fetchone()[0] == 0:
                now_iso = datetime.datetime.utcnow().isoformat()
                seed_nodes = [
                    # 1. Germany - Frankfurt VLESS WS
                    ("node-de-01", "🇩🇪 Frankfurt Edge 01", "vless", "de.edge.platform.io", 443, 
                     "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", None, None, 0, "ws", "tls", 
                     "de.edge.platform.io", "de.edge.platform.io", "/vless-ws", None, None, "chrome", None, None, None, 
                     "DE", 68, 0.0, 99.9, "healthy", 96.0, 1, "hash-de-01", now_iso),
                     
                    # 2. Netherlands - Amsterdam VLESS Reality (Vision)
                    ("node-nl-02", "🇳🇱 Amsterdam Reality 02", "vless", "nl.edge.platform.io", 443,
                     "b1eebc99-9c0b-4ef8-bb6d-6bb9bd380b22", None, None, 0, "tcp", "reality",
                     "www.microsoft.com", None, None, None, "xtls-rprx-vision", "chrome", 
                     "w8zR-8qVdC-examplePublicKeyOnlyForDocPurpose1234", "abcd1234", "/",
                     "NL", 74, 0.0, 99.8, "healthy", 98.0, 1, "hash-nl-02", now_iso),

                    # 3. United States - New York Trojan WS
                    ("node-us-03", "🇺🇸 New York CDN 03", "trojan", "us.edge.platform.io", 443,
                     None, "passTrojan123", None, 0, "ws", "tls",
                     "us.edge.platform.io", "us.edge.platform.io", "/tr-ws", None, None, "chrome", None, None, None,
                     "US", 108, 0.0, 99.7, "healthy", 88.0, 1, "hash-us-03", now_iso),

                    # 4. Finland - Helsinki Shadowsocks
                    ("node-fi-04", "🇫🇮 Helsinki Core 04", "shadowsocks", "fi.edge.platform.io", 8388,
                     None, "mySecurePass123", "aes-256-gcm", 0, "tcp", "none",
                     None, None, None, None, None, "chrome", None, None, None,
                     "FI", 89, 0.0, 99.5, "healthy", 90.0, 1, "hash-fi-04", now_iso),

                    # 5. United Kingdom - London VLESS gRPC
                    ("node-gb-05", "🇬🇧 London Speed 05", "vless", "gb.edge.platform.io", 443,
                     "c2eebc99-9c0b-4ef8-bb6d-6bb9bd380c33", None, None, 0, "grpc", "tls",
                     "gb.edge.platform.io", None, None, "vless-grpc", None, "chrome", None, None, None,
                     "GB", 82, 0.0, 99.6, "healthy", 92.0, 1, "hash-gb-05", now_iso),

                    # 6. France - Paris VMess WS
                    ("node-fr-06", "🇫🇷 Paris Cloud 06", "vmess", "fr.edge.platform.io", 443,
                     "d3eebc99-9c0b-4ef8-bb6d-6bb9bd380d44", None, "auto", 0, "ws", "tls",
                     "fr.edge.platform.io", "fr.edge.platform.io", "/vmess-ws", None, None, "chrome", None, None, None,
                     "FR", 80, 0.0, 99.6, "healthy", 91.0, 1, "hash-fr-06", now_iso),

                    # 7. Turkey - Istanbul Low Ping
                    ("node-tr-07", "🇹🇷 Istanbul Near 07", "vless", "tr.edge.platform.io", 443,
                     "e4eebc99-9c0b-4ef8-bb6d-6bb9bd380e55", None, None, 0, "ws", "tls",
                     "tr.edge.platform.io", "tr.edge.platform.io", "/tr-near", None, None, "chrome", None, None, None,
                     "TR", 52, 0.0, 99.9, "healthy", 97.0, 1, "hash-tr-07", now_iso),

                    # 8. Singapore - Asia Fast
                    ("node-sg-08", "🇸🇬 Singapore Ultra 08", "trojan", "sg.edge.platform.io", 443,
                     None, "passTrojanSg88", None, 0, "ws", "tls",
                     "sg.edge.platform.io", "sg.edge.platform.io", "/sg-ws", None, None, "chrome", None, None, None,
                     "SG", 115, 0.0, 99.4, "healthy", 87.0, 1, "hash-sg-08", now_iso)
                ]
                cursor.executemany("""
                    INSERT INTO nodes (
                        id, name, protocol, server, port, uuid, password, cipher, alter_id, network, tls,
                        sni, host, path, service_name, flow, fingerprint, reality_public_key, reality_short_id, reality_spider_x,
                        country, latency, packet_loss, uptime, health, score, active, raw_config_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, seed_nodes)
                conn.commit()

            ACTIVE_DB_PATH = path_candidate
            conn.close()
            return
        except Exception:
            continue

init_db()

# --- Users API ---
def get_all_users() -> List[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY id DESC")
        return [dict(row) for row in cursor.fetchall()]

def get_user_by_uuid(user_uuid: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE uuid = ? AND is_active = 1", (user_uuid.strip().lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_password_hash(p_hash: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE password_hash = ? AND is_active = 1", (p_hash.strip().lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username.strip(),))
        row = cursor.fetchone()
        return dict(row) if row else None

def create_user(username: str, user_uuid: Optional[str] = None, password: Optional[str] = None,
                expires_at: Optional[str] = None, country_preset: str = 'iran', notes: str = '') -> Dict[str, Any]:
    if not user_uuid:
        user_uuid = str(uuid.uuid4())
    else:
        user_uuid = user_uuid.strip().lower()

    if not password:
        password = str(uuid.uuid4())[:12]
    
    p_hash = hashlib.sha224(password.encode('utf-8')).hexdigest()
    created_at = datetime.datetime.utcnow().isoformat()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, uuid, password, password_hash, created_at, expires_at, is_active, country_preset, notes)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
        """, (username.strip(), user_uuid, password, p_hash, created_at, expires_at, country_preset, notes))
        conn.commit()
        user_id = cursor.lastrowid
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return dict(cursor.fetchone())

def delete_user(user_id: int) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return cursor.rowcount > 0

def toggle_user_status(user_id: int) -> Optional[int]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT is_active FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        new_status = 0 if row["is_active"] == 1 else 1
        cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        return new_status

def add_traffic(user_id: int, up: int, down: int):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET upload_bytes = upload_bytes + ?, download_bytes = download_bytes + ?
            WHERE id = ?
        """, (up, down, user_id))
        conn.commit()

# --- Nodes Management API ---
def get_all_nodes(country: Optional[str] = None, active_only: bool = True) -> List[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM nodes"
        params = []
        conditions = []
        if active_only:
            conditions.append("active = 1")
        if country:
            countries = [c.strip().upper() for c in country.split(',') if c.strip()]
            if countries:
                placeholders = ",".join("?" for _ in countries)
                conditions.append(f"UPPER(country) IN ({placeholders})")
                params.extend(countries)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY score DESC, latency ASC"
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

def add_node(node_data: Dict[str, Any]) -> Dict[str, Any]:
    node_id = node_data.get('id') or str(uuid.uuid4())
    now_iso = datetime.datetime.utcnow().isoformat()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO nodes (
                id, name, protocol, server, port, uuid, password, cipher, alter_id, network, tls,
                sni, host, path, service_name, flow, fingerprint, reality_public_key, reality_short_id, reality_spider_x,
                country, latency, packet_loss, uptime, health, score, active, raw_config_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            node_id,
            node_data.get('name', 'Proxy Node'),
            node_data.get('protocol', 'vless'),
            node_data.get('server', ''),
            int(node_data.get('port', 443)),
            node_data.get('uuid'),
            node_data.get('password'),
            node_data.get('cipher'),
            int(node_data.get('alter_id', 0)),
            node_data.get('network', 'tcp'),
            node_data.get('tls', 'none'),
            node_data.get('sni'),
            node_data.get('host'),
            node_data.get('path'),
            node_data.get('service_name'),
            node_data.get('flow'),
            node_data.get('fingerprint', 'chrome'),
            node_data.get('reality_public_key'),
            node_data.get('reality_short_id'),
            node_data.get('reality_spider_x'),
            node_data.get('country', 'UN'),
            int(node_data.get('latency', 70)),
            float(node_data.get('packet_loss', 0.0)),
            float(node_data.get('uptime', 99.9)),
            node_data.get('health', 'healthy'),
            float(node_data.get('score', 90.0)),
            1 if node_data.get('active', True) else 0,
            node_data.get('raw_config_hash') or hashlib.sha256(f"{node_id}:{now_iso}".encode()).hexdigest()[:16],
            now_iso
        ))
        conn.commit()
        cursor.execute("SELECT * FROM nodes WHERE id = ?", (node_id,))
        return dict(cursor.fetchone())

def delete_node(node_id: str) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
        conn.commit()
        return cursor.rowcount > 0
