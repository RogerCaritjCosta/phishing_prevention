import json
import os

_cache: dict[str, dict] = {}
_SUPPORTED = {"es", "ca", "en"}
_DIR = os.path.dirname(__file__)


def load_translations(lang: str) -> dict | None:
    if lang not in _SUPPORTED:
        return None
    if lang not in _cache:
        path = os.path.join(_DIR, f"{lang}.json")
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            _cache[lang] = json.load(f)
    return _cache[lang]
