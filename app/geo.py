"""
Geo IP, Country Flags, and Region Detection
"""
from typing import List, Dict, Any

def get_country_flag_emoji(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        return "🌐"
    try:
        return "".join(chr(127397 + ord(c)) for c in country_code.upper())
    except Exception:
        return "🌐"

DEFAULT_LOCATIONS: List[Dict[str, Any]] = [
    {"code": "DE", "name": "Germany", "name_fa": "آلمان", "flag": "🇩🇪", "active": True},
    {"code": "NL", "name": "Netherlands", "name_fa": "هلند", "flag": "🇳🇱", "active": True},
    {"code": "US", "name": "United States", "name_fa": "آمریکا", "flag": "🇺🇸", "active": True},
    {"code": "FI", "name": "Finland", "name_fa": "فنلاند", "flag": "🇫🇮", "active": True},
    {"code": "TR", "name": "Turkey", "name_fa": "ترکیه", "flag": "🇹🇷", "active": True},
    {"code": "GB", "name": "United Kingdom", "name_fa": "انگلستان", "flag": "🇬🇧", "active": True},
    {"code": "FR", "name": "France", "name_fa": "فرانسه", "flag": "🇫🇷", "active": True},
    {"code": "SG", "name": "Singapore", "name_fa": "سنگاپور", "flag": "🇸🇬", "active": True},
    {"code": "JP", "name": "Japan", "name_fa": "ژاپن", "flag": "🇯🇵", "active": True},
    {"code": "AE", "name": "UAE", "name_fa": "امارات", "flag": "🇦🇪", "active": True}
]

COUNTRY_KEYWORDS = [
    ("GERMANY", "DE"), ("FRANKFURT", "DE"), ("BERLIN", "DE"), ("DE-", "DE"), ("-DE", "DE"),
    ("NETHERLANDS", "NL"), ("AMSTERDAM", "NL"), ("NL-", "NL"), ("-NL", "NL"),
    ("UNITED STATES", "US"), ("AMERICA", "US"), ("NEW YORK", "US"), ("LOS ANGELES", "US"), ("US-", "US"), ("-US", "US"),
    ("FINLAND", "FI"), ("HELSINKI", "FI"), ("FI-", "FI"), ("-FI", "FI"),
    ("TURKEY", "TR"), ("ISTANBUL", "TR"), ("TR-", "TR"), ("-TR", "TR"),
    ("UNITED KINGDOM", "GB"), ("LONDON", "GB"), ("UK-", "GB"), ("-UK", "GB"), ("GB-", "GB"),
    ("FRANCE", "FR"), ("PARIS", "FR"), ("FR-", "FR"), ("-FR", "FR"),
    ("SINGAPORE", "SG"), ("SG-", "SG"), ("-SG", "SG"),
    ("JAPAN", "JP"), ("TOKYO", "JP"), ("JP-", "JP"), ("-JP", "JP"),
    ("DUBAI", "AE"), ("UAE", "AE"), ("AE-", "AE"),
    ("IRAN", "IR"), ("TEHRAN", "IR"), ("IR-", "IR")
]

def infer_country_code(name: str, host: str) -> str:
    upper = f"{name} {host}".upper()
    for kw, code in COUNTRY_KEYWORDS:
        if kw in upper:
            return code
    return "UN"
