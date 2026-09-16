"""
Proxy Config Formats: Sing-box, Clash Meta, Base64, Plain, WireGuard
"""
import json
import base64
import urllib.parse
from typing import List, Dict, Any, Optional

def node_to_uri(node: Dict[str, Any]) -> str:
    proto = node.get('protocol')
    name = node.get('name', 'Node')
    clean_tag = urllib.parse.quote(name)
    server = node.get('server', '')
    port = node.get('port', 443)
    
    if proto == 'vless':
        params = {
            'type': node.get('network', 'tcp'),
            'security': node.get('tls', 'none')
        }
        if node.get('sni'): params['sni'] = node['sni']
        if node.get('host'): params['host'] = node['host']
        if node.get('path'): params['path'] = node['path']
        if node.get('service_name'): params['serviceName'] = node['service_name']
        if node.get('flow'): params['flow'] = node['flow']
        if node.get('fingerprint'): params['fp'] = node['fingerprint']
        if node.get('reality_public_key'): params['pbk'] = node['reality_public_key']
        if node.get('reality_short_id'): params['sid'] = node['reality_short_id']
        if node.get('reality_spider_x'): params['spx'] = node['reality_spider_x']
        q = urllib.parse.urlencode(params)
        return f"vless://{node.get('uuid')}@{server}:{port}?{q}#{clean_tag}"

    if proto == 'trojan':
        params = {
            'type': node.get('network', 'tcp'),
            'security': 'tls'
        }
        if node.get('sni'): params['sni'] = node['sni']
        if node.get('host'): params['host'] = node['host']
        if node.get('path'): params['path'] = node['path']
        if node.get('fingerprint'): params['fp'] = node['fingerprint']
        q = urllib.parse.urlencode(params)
        return f"trojan://{node.get('password')}@{server}:{port}?{q}#{clean_tag}"

    if proto == 'vmess':
        vmess_obj = {
            "v": "2",
            "ps": name,
            "add": server,
            "port": port,
            "id": node.get('uuid'),
            "aid": node.get('alter_id', 0),
            "scy": node.get('cipher', 'auto'),
            "net": node.get('network', 'tcp'),
            "type": "none",
            "host": node.get('host', ''),
            "path": node.get('path', ''),
            "tls": "tls" if node.get('tls') == 'tls' else '',
            "sni": node.get('sni', '')
        }
        b64 = base64.b64encode(json.dumps(vmess_obj).encode('utf-8')).decode('utf-8')
        return f"vmess://{b64}"

    if proto == 'shadowsocks':
        auth = base64.b64encode(f"{node.get('cipher', 'aes-256-gcm')}:{node.get('password', '')}".encode('utf-8')).decode('utf-8')
        return f"ss://{auth}@{server}:{port}#{clean_tag}"

    return ""

def generate_base64_subscription(nodes: List[Dict[str, Any]]) -> str:
    uris = [node_to_uri(n) for n in nodes if node_to_uri(n)]
    return base64.b64encode("\n".join(uris).encode('utf-8')).decode('utf-8')

def generate_plain_subscription(nodes: List[Dict[str, Any]]) -> str:
    uris = [node_to_uri(n) for n in nodes if node_to_uri(n)]
    return "\n".join(uris)

def generate_singbox_config(nodes: List[Dict[str, Any]], clean_ips: Optional[List[str]] = None) -> str:
    outbounds = []
    node_tags = []
    
    for n in nodes:
        tag = n.get('name', 'Node').replace(':', '-')
        node_tags.append(tag)
        proto = n.get('protocol')
        server = n.get('server')
        port = n.get('port')
        
        if proto == 'vless':
            outbound = {
                "type": "vless",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": n.get('uuid'),
                "network": n.get('network') if n.get('network') in ['ws', 'grpc'] else 'tcp'
            }
            if n.get('flow'):
                outbound['flow'] = n['flow']
            
            tls_mode = n.get('tls', 'none')
            if tls_mode == 'tls':
                outbound['tls'] = {
                    "enabled": True,
                    "server_name": n.get('sni') or server,
                    "utls": {"enabled": True, "fingerprint": n.get('fingerprint', 'chrome')}
                }
            elif tls_mode == 'reality':
                outbound['tls'] = {
                    "enabled": True,
                    "server_name": n.get('sni') or server,
                    "reality": {
                        "enabled": True,
                        "public_key": n.get('reality_public_key', ''),
                        "short_id": n.get('reality_short_id', '')
                    },
                    "utls": {"enabled": True, "fingerprint": n.get('fingerprint', 'chrome')}
                }
            if n.get('network') == 'ws':
                outbound['transport'] = {
                    "type": "ws",
                    "path": n.get('path', '/'),
                    "headers": {"Host": n['host']} if n.get('host') else None
                }
            elif n.get('network') == 'grpc':
                outbound['transport'] = {
                    "type": "grpc",
                    "service_name": n.get('service_name', '')
                }
            outbounds.append(outbound)
            
        elif proto == 'trojan':
            outbound = {
                "type": "trojan",
                "tag": tag,
                "server": server,
                "server_port": port,
                "password": n.get('password'),
                "network": n.get('network') if n.get('network') in ['ws', 'grpc'] else 'tcp',
                "tls": {
                    "enabled": True,
                    "server_name": n.get('sni') or server,
                    "utls": {"enabled": True, "fingerprint": n.get('fingerprint', 'chrome')}
                }
            }
            if n.get('network') == 'ws':
                outbound['transport'] = {
                    "type": "ws",
                    "path": n.get('path', '/'),
                    "headers": {"Host": n['host']} if n.get('host') else None
                }
            outbounds.append(outbound)
            
        elif proto == 'vmess':
            outbound = {
                "type": "vmess",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": n.get('uuid'),
                "security": n.get('cipher', 'auto'),
                "alter_id": n.get('alter_id', 0),
                "network": "ws" if n.get('network') == 'ws' else "tcp"
            }
            if n.get('tls') == 'tls':
                outbound['tls'] = {
                    "enabled": True,
                    "server_name": n.get('sni') or server
                }
            if n.get('network') == 'ws':
                outbound['transport'] = {
                    "type": "ws",
                    "path": n.get('path', '/'),
                    "headers": {"Host": n['host']} if n.get('host') else None
                }
            outbounds.append(outbound)

        elif proto == 'shadowsocks':
            outbounds.append({
                "type": "shadowsocks",
                "tag": tag,
                "server": server,
                "server_port": port,
                "method": n.get('cipher', 'aes-256-gcm'),
                "password": n.get('password')
            })

    selector_outbounds = [
        {"type": "selector", "tag": "🌐 Select Proxy", "outbounds": ["⚡ Auto Fastest"] + node_tags + ["direct"]},
        {"type": "urltest", "tag": "⚡ Auto Fastest", "outbounds": node_tags if node_tags else ["direct"], "url": "http://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
        {"type": "dns", "tag": "dns-out"}
    ]

    config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns-remote", "address": "https://1.1.1.1/dns-query"},
                {"tag": "dns-direct", "address": "178.22.122.100", "detour": "direct"}
            ],
            "rules": [{"outbound": "any", "server": "dns-direct"}]
        },
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080, "sniff": True},
            {"type": "tun", "tag": "tun-in", "interface_name": "tun0", "inet4_address": "172.19.0.1/30", "auto_route": True, "strict_route": True, "mtu": 1400, "stack": "system", "sniff": True}
        ],
        "outbounds": selector_outbounds + outbounds,
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"clashing_mode": "Direct", "outbound": "direct"},
                {"clashing_mode": "Global", "outbound": "🌐 Select Proxy"},
                {"geoip": "ir", "outbound": "direct"},
                {"geosite": "ir", "outbound": "direct"}
            ],
            "auto_detect_interface": True
        }
    }
    return json.dumps(config, indent=2, ensure_ascii=False)

def generate_clash_meta_config(nodes: List[Dict[str, Any]]) -> str:
    proxy_items = []
    proxy_names = []
    
    for n in nodes:
        clean_name = n.get('name', 'Node').replace('"', '').replace("'", "").replace(":", "-").strip()
        proxy_names.append(f'"{clean_name}"')
        proto = n.get('protocol')
        server = n.get('server')
        port = n.get('port')
        
        if proto == 'vless':
            lines = [
                f'  - name: "{clean_name}"',
                '    type: vless',
                f'    server: {server}',
                f'    port: {port}',
                f'    uuid: {n.get("uuid")}',
                '    udp: true'
            ]
            if n.get('tls') == 'tls':
                lines.append('    tls: true')
                lines.append(f'    servername: {n.get("sni") or server}')
                lines.append(f'    client-fingerprint: {n.get("fingerprint", "chrome")}')
            elif n.get('tls') == 'reality':
                lines.append('    tls: true')
                lines.append(f'    servername: {n.get("sni") or server}')
                lines.append('    reality-opts:')
                lines.append(f'      public-key: {n.get("reality_public_key", "")}')
                lines.append(f'      short-id: "{n.get("reality_short_id", "")}"')
                lines.append(f'    client-fingerprint: {n.get("fingerprint", "chrome")}')
            if n.get('flow'):
                lines.append(f'    flow: {n["flow"]}')
            if n.get('network') == 'ws':
                lines.append('    network: ws')
                lines.append('    ws-opts:')
                lines.append(f'      path: "{n.get("path", "/")}"')
                if n.get('host'):
                    lines.append('      headers:')
                    lines.append(f'        Host: "{n["host"]}"')
            elif n.get('network') == 'grpc':
                lines.append('    network: grpc')
                lines.append('    grpc-opts:')
                lines.append(f'      grpc-service-name: "{n.get("service_name", "")}"')
            proxy_items.append("\n".join(lines))
            
        elif proto == 'trojan':
            lines = [
                f'  - name: "{clean_name}"',
                '    type: trojan',
                f'    server: {server}',
                f'    port: {port}',
                f'    password: "{n.get("password")}"',
                '    udp: true',
                f'    sni: {n.get("sni") or server}',
                f'    client-fingerprint: {n.get("fingerprint", "chrome")}'
            ]
            if n.get('network') == 'ws':
                lines.append('    network: ws')
                lines.append('    ws-opts:')
                lines.append(f'      path: "{n.get("path", "/")}"')
                if n.get('host'):
                    lines.append('      headers:')
                    lines.append(f'        Host: "{n["host"]}"')
            proxy_items.append("\n".join(lines))
            
        elif proto == 'vmess':
            lines = [
                f'  - name: "{clean_name}"',
                '    type: vmess',
                f'    server: {server}',
                f'    port: {port}',
                f'    uuid: {n.get("uuid")}',
                f'    alterId: {n.get("alter_id", 0)}',
                f'    cipher: {n.get("cipher", "auto")}',
                '    udp: true'
            ]
            if n.get('tls') == 'tls':
                lines.append('    tls: true')
                lines.append(f'    servername: {n.get("sni") or server}')
            if n.get('network') == 'ws':
                lines.append('    network: ws')
                lines.append('    ws-opts:')
                lines.append(f'      path: "{n.get("path", "/")}"')
                if n.get('host'):
                    lines.append('      headers:')
                    lines.append(f'        Host: "{n["host"]}"')
            proxy_items.append("\n".join(lines))

        elif proto == 'shadowsocks':
            lines = [
                f'  - name: "{clean_name}"',
                '    type: ss',
                f'    server: {server}',
                f'    port: {port}',
                f'    cipher: {n.get("cipher", "aes-256-gcm")}',
                f'    password: "{n.get("password")}"',
                '    udp: true'
            ]
            proxy_items.append("\n".join(lines))

    proxies_section = "\n".join(proxy_items)
    if proxy_names:
        proxies_list_lines = "\n".join([f"      - {p}" for p in proxy_names])
    else:
        proxies_list_lines = '      - "DIRECT"'

    return f"""port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: false
mode: rule
log-level: info
ipv6: false

dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - 178.22.122.100

proxies:
{proxies_section}

proxy-groups:
  - name: "🌐 PROXY"
    type: select
    proxies:
      - "⚡ AUTO-FASTEST"
{proxies_list_lines}
      - "DIRECT"

  - name: "⚡ AUTO-FASTEST"
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
{proxies_list_lines}

rules:
  - DOMAIN-SUFFIX,ir,DIRECT
  - GEOIP,IR,DIRECT
  - MATCH,🌐 PROXY
"""

def generate_wireguard_config(endpoint="162.159.192.1:2408", private_key=""):
    priv = private_key or "aEXAMPLEpRiVaTeKeY0123456789abcdefghijklmn="
    conf = f"""[Interface]
PrivateKey = {priv}
Address = 172.16.0.2/32, 2606:4700:110:8f81:8595:2f27:850f:4f40/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1400

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    return conf
