APPROVED_SOURCES = {
    "https://www.cloudflare.com/cdn-cgi/trace": {
        "format": "trace",
        "country_field": "loc",
        "ip_field": "ip",
    },
    "https://api.ip.sb/geoip": {
        "format": "json",
        "country_field": "country_code",
        "ip_field": "ip",
    },
}


def validate_source(source):
    expected = APPROVED_SOURCES.get(source.get("url"))
    if expected is None:
        raise ValueError("Для проверки IP разрешены только утверждённые зарубежные API Cloudflare и IP.SB")
    if any(source.get(key) != value for key, value in expected.items()):
        raise ValueError("Параметры ответа источника не соответствуют утверждённому API")
