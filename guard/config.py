import json
import math
import platform
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent


def system_name():
    names = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}
    if platform.system() not in names:
        raise ValueError("Поддерживаются macOS, Windows и Linux")
    return names[platform.system()]


def validate_proxy(value):
    if value in ("auto", "direct"):
        return value
    url = urlsplit(value)
    if url.scheme not in ("http", "https", "socks5h") or url.hostname not in ("127.0.0.1", "localhost", "::1") or not url.port or url.username or url.password:
        raise ValueError("proxy: auto, direct или адрес локального HTTP/SOCKS5h-прокси без пароля")
    return value


def resolve_proxy(value):
    validate_proxy(value)
    if value != "auto":
        return "" if value == "direct" else value
    proxies = urllib.request.getproxies()
    for key in ("https", "http", "all", "socks"):
        proxy = proxies.get(key)
        if not proxy:
            continue
        if key == "socks" and "://" not in proxy:
            proxy = "socks5h://" + proxy
        if proxy.startswith('socks://'):
            proxy = 'socks5h://' + proxy[len('socks://'):]
        validate_proxy(proxy)
        return proxy
    return ""


def load():
    cfg = json.loads((ROOT / "configs/base.json").read_text(encoding="utf-8"))
    name = system_name()
    cfg.update(json.loads((ROOT / "configs" / f"{name}.json").read_text(encoding="utf-8")))
    if set(cfg) != {"check_interval", "request_timeout", "startup_timeout", "proxy", "platform"} or cfg["platform"] != name:
        raise ValueError("Некорректный конфиг программы")
    for key in ("check_interval", "request_timeout", "startup_timeout"):
        value = cfg[key]
        if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or not 0.2 <= value <= 60:
            raise ValueError(f"Некорректный {key}")
    validate_proxy(cfg["proxy"])
    cfg["os"] = name
    return cfg
