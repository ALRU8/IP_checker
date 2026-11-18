import ipaddress
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .countries import COUNTRIES
from .sources import APPROVED_SOURCES, validate_source


@dataclass(frozen=True)
class Result:
    name: str
    ip: str = ""
    country: str = ""
    error: str = ""
    timezone: str = ""

    @property
    def safe(self):
        return not self.error and self.country in COUNTRIES and self.country != "RU"


def sources():
    return [dict(name=name, url=url, **APPROVED_SOURCES[url]) for name, url in
            (("Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace"), ("IP.SB", "https://api.ip.sb/geoip"))]


def parse(source, body):
    if source["format"] == "trace":
        data = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
    else:
        data = json.loads(body)
    if not isinstance(data, dict) or data.get("error") or data.get("success") is False:
        raise ValueError("Сервис вернул ошибку")
    country = data.get(source["country_field"], "")
    if not isinstance(country, str) or country.upper() not in COUNTRIES:
        raise ValueError("Сервис не сообщил известную страну")
    address = ipaddress.ip_address(data.get(source["ip_field"], ""))
    if not address.is_global or address.is_multicast:
        raise ValueError("Сервис не сообщил публичный IP")
    zone = data.get('timezone', '')
    zone = zone if isinstance(zone, str) and len(zone) <= 120 and re.fullmatch(r'[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*', zone) else ''
    return Result(source["name"], str(address), country.upper(), timezone=zone)


def curl_path():
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/curl.exe" if os.name == "nt" else Path("/usr/bin/curl")
    result = str(path) if path.is_file() else shutil.which("curl")
    if not result:
        raise RuntimeError("Не найден curl. Установи curl перед запуском")
    return result


def check(source, timeout, proxy):
    try:
        validate_source(source)
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        cmd = [curl_path(), "--disable", "--silent", "--show-error", "--fail", "--proto", "=https",
               "--user-agent", "ALRU8-IP-Monitor/2.0", "--max-time", str(timeout),
               "--connect-timeout", str(timeout), "--max-filesize", "65536", "--proxy", proxy,
               "--noproxy", "" if proxy else "*", source["url"]]
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout + 1)
        if result.returncode:
            return Result(source["name"], error=f"Нет ответа (curl {result.returncode})")
        return parse(source, result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as exc:
        return Result(source.get("name", "API"), error=str(exc)[:150])
