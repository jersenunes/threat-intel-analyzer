from utils.utils import read_a_json
from typing import Dict, List, Any
import os


def load_indicators_from_json(path: str) -> Dict[str, List[Any]]:
    data = read_a_json(path=path)

    indicators = {
        "ip": [],
        "domain": [],
        "url": [],
        "hash": [],
        "file": []
    }

    indicators["ip"] = data.get("ip", [])
    indicators["domain"] = data.get("domain", [])
    indicators["url"] = data.get("url", [])
    indicators["file"] = data.get("file", [])

    hash_block = data.get("hash", {})
    for hash_type in ("sha256", "sha1", "md5"):
        for value in hash_block.get(hash_type, []):
            indicators["hash"].append({
                "type": hash_type,
                "value": value
            })

    return indicators
