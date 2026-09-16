import asyncio
import struct
import socket
import uuid
import logging
from typing import Optional, Tuple
from fastapi import WebSocket, WebSocketDisconnect
from app.database import get_user_by_uuid, get_user_by_password_hash, add_traffic

logger = logging.getLogger("milijon.proxy")
CHUNK_SIZE = 32768

async def pipe_ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, user_id: int):
    uploaded = 0
    try:
        while True:
            data = await websocket.receive_bytes()
            if not data:
                break
            writer.write(data)
            await writer.drain()
            uploaded += len(data)
    except (WebSocketDisconnect, asyncio.CancelledError, ConnectionResetError):
        pass
    except Exception as e:
        logger.debug(f"WS->TCP error: {e}")
    finally:
        if uploaded > 0:
            add_traffic(user_id, up=uploaded, down=0)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def pipe_tcp_to_ws(reader: asyncio.StreamReader, websocket: WebSocket, user_id: int, initial_prefix: bytes = b""):
    downloaded = 0
    first_packet = True
    try:
        while True:
            data = await reader.read(CHUNK_SIZE)
            if not data:
                break
            if first_packet and initial_prefix:
                await websocket.send_bytes(initial_prefix + data)
                first_packet = False
            else:
                await websocket.send_bytes(data)
            downloaded += len(data)
    except (WebSocketDisconnect, asyncio.CancelledError, ConnectionResetError):
        pass
    except Exception as e:
        logger.debug(f"TCP->WS error: {e}")
    finally:
        if downloaded > 0:
            add_traffic(user_id, up=0, down=downloaded)
        try:
            await websocket.close()
        except Exception:
            pass

async def connect_remote_tcp(target_host: str, target_port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.wait_for(
        asyncio.open_connection(target_host, target_port),
        timeout=10.0
    )

async def handle_vless_websocket(websocket: WebSocket):
    await websocket.accept(subprotocol=websocket.headers.get("sec-websocket-protocol"))
    try:
        first_chunk = await websocket.receive_bytes()
        if len(first_chunk) < 18:
            await websocket.close(code=1008)
            return

        version = first_chunk[0]
        raw_uuid = first_chunk[1:17]
        user_uuid_str = str(uuid.UUID(bytes=raw_uuid)).lower()

        user = get_user_by_uuid(user_uuid_str)
        if not user or user["is_active"] != 1:
            await websocket.close(code=1008)
            return

        user_id = user["id"]
        idx = 17
        proto_opt_len = first_chunk[idx]
        idx += 1 + proto_opt_len
        cmd = first_chunk[idx]
        idx += 1

        if cmd != 1:
            await websocket.close(code=1003)
            return

        target_port = struct.unpack("!H", first_chunk[idx:idx+2])[0]
        idx += 2
        addr_type = first_chunk[idx]
        idx += 1

        if addr_type == 1:
            target_host = socket.inet_ntoa(first_chunk[idx:idx+4])
            idx += 4
        elif addr_type == 2:
            domain_len = first_chunk[idx]
            idx += 1
            target_host = first_chunk[idx:idx+domain_len].decode("utf-8", errors="ignore")
            idx += domain_len
        elif addr_type == 3:
            target_host = socket.inet_ntop(socket.AF_INET6, first_chunk[idx:idx+16])
            idx += 16
        else:
            await websocket.close(code=1003)
            return

        reader, writer = await connect_remote_tcp(target_host, target_port)
        initial_payload = first_chunk[idx:]
        if initial_payload:
            writer.write(initial_payload)
            await writer.drain()

        resp_header = bytes([version, 0])
        await asyncio.gather(
            pipe_ws_to_tcp(websocket, writer, user_id),
            pipe_tcp_to_ws(reader, websocket, user_id, initial_prefix=resp_header)
        )
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass

async def handle_trojan_websocket(websocket: WebSocket):
    await websocket.accept(subprotocol=websocket.headers.get("sec-websocket-protocol"))
    try:
        first_chunk = await websocket.receive_bytes()
        if len(first_chunk) < 58:
            await websocket.close(code=1008)
            return

        hex_hash = first_chunk[:56].decode("ascii", errors="ignore").lower()
        user = get_user_by_password_hash(hex_hash)
        if not user or user["is_active"] != 1:
            await websocket.close(code=1008)
            return

        user_id = user["id"]
        idx = 58
        cmd = first_chunk[idx]
        idx += 1
        addr_type = first_chunk[idx]
        idx += 1

        if addr_type == 1:
            target_host = socket.inet_ntoa(first_chunk[idx:idx+4])
            idx += 4
        elif addr_type == 3:
            domain_len = first_chunk[idx]
            idx += 1
            target_host = first_chunk[idx:idx+domain_len].decode("utf-8", errors="ignore")
            idx += domain_len
        elif addr_type == 4:
            target_host = socket.inet_ntop(socket.AF_INET6, first_chunk[idx:idx+16])
            idx += 16
        else:
            await websocket.close(code=1003)
            return

        target_port = struct.unpack("!H", first_chunk[idx:idx+2])[0]
        idx += 4

        reader, writer = await connect_remote_tcp(target_host, target_port)
        initial_payload = first_chunk[idx:]
        if initial_payload:
            writer.write(initial_payload)
            await writer.drain()

        await asyncio.gather(
            pipe_ws_to_tcp(websocket, writer, user_id),
            pipe_tcp_to_ws(reader, websocket, user_id)
        )
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass
