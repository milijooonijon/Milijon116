"""
Unified Subscription Generator Engine
Supports: Multi-Location Selection, Sorting Strategies, Iran Optimizations
"""
import random
import json
from typing import List, Dict, Any, Optional
from app.config import PRESET_CLEAN_IPS, PRESET_FRAGMENT
from app.proxy_formats import (
    generate_singbox_config,
    generate_clash_meta_config,
    generate_base64_subscription,
    generate_plain_subscription,
    generate_wireguard_config
)

def apply_iran_optimizations(nodes: List[Dict[str, Any]], clean_ips: List[str]) -> List[Dict[str, Any]]:
    optimized = []
    for n in nodes:
        node = dict(n)
        if node.get('network') in ['ws', 'grpc'] and node.get('sni') and clean_ips:
            node['server'] = random.choice(clean_ips)
        if node.get('tls') == 'reality' and not node.get('flow'):
            node['flow'] = 'xtls-rprx-vision'
        optimized.append(node)
    return optimized

def sort_nodes(nodes: List[Dict[str, Any]], strategy: str = "balanced") -> List[Dict[str, Any]]:
    cloned = [dict(n) for n in nodes]
    if strategy in ["fastest", "lowest-latency"]:
        cloned.sort(key=lambda x: x.get('latency', 9999))
    elif strategy == "country":
        by_country = {}
        for n in cloned:
            c = n.get('country', 'UN')
            by_country.setdefault(c, []).append(n)
        interleaved = []
        has_items = True
        while has_items:
            has_items = False
            for c_list in by_country.values():
                if c_list:
                    interleaved.append(c_list.pop(0))
                    has_items = True
        return interleaved
    else:
        cloned.sort(key=lambda x: x.get('score', 0), reverse=True)
    return cloned

def generate_subscription_response(
    nodes: List[Dict[str, Any]],
    target: str = "singbox",
    strategy: str = "balanced",
    iran_optimized: bool = True
) -> Dict[str, Any]:
    selected_nodes = sort_nodes(nodes, strategy)
    clean_ips = PRESET_CLEAN_IPS.get("iran", [])
    if iran_optimized:
        selected_nodes = apply_iran_optimizations(selected_nodes, clean_ips)
        
    t = target.lower().strip()
    if t in ["singbox", "sb"]:
        content = generate_singbox_config(selected_nodes, clean_ips)
        media_type = "application/json; charset=utf-8"
        ext = "json"
    elif t in ["clash", "clashmeta", "meta"]:
        content = generate_clash_meta_config(selected_nodes)
        media_type = "text/yaml; charset=utf-8"
        ext = "yaml"
    elif t in ["raw", "plain"]:
        content = generate_plain_subscription(selected_nodes)
        media_type = "text/plain; charset=utf-8"
        ext = "txt"
    elif t in ["wireguard", "warp"]:
        content = generate_wireguard_config()
        media_type = "text/plain; charset=utf-8"
        ext = "conf"
    elif t == "json":
        content = json.dumps({"total": len(selected_nodes), "nodes": selected_nodes}, indent=2, ensure_ascii=False)
        media_type = "application/json; charset=utf-8"
        ext = "json"
    else:
        content = generate_base64_subscription(selected_nodes)
        media_type = "text/plain; charset=utf-8"
        ext = "txt"
        
    return {
        "content": content,
        "media_type": media_type,
        "ext": ext,
        "count": len(selected_nodes)
    }
