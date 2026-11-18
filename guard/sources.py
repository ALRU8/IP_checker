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
        "timezone_field": "timezone",
    },
    "https://1.1.1.1/cdn-cgi/trace": {
        "format": "trace",
        "country_field": "loc",
        "ip_field": "ip",
    },
    "https://get.geojs.io/v1/ip/geo.json": {
        "format": "json",
        "country_field": "country_code",
        "ip_field": "ip",
        "timezone_field": "timezone",
    },
    "https://ipinfo.io/json": {
        "format": "json",
        "country_field": "country",
        "ip_field": "ip",
        "timezone_field": "timezone",
    },
    "https://ipwho.is/": {
        "format": "json",
        "country_field": "country_code",
        "ip_field": "ip",
    },
    "https://api.country.is/": {
        "format": "json",
        "country_field": "country",
        "ip_field": "ip",
    },
    "https://ifconfig.co/json": {
        "format": "json",
        "country_field": "country_iso",
        "ip_field": "ip",
        "timezone_field": "time_zone",
    },
}

SOURCE_NAMES = (
    ("Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace"),
    ("IP.SB", "https://api.ip.sb/geoip"),
    ("Cloudflare IP", "https://1.1.1.1/cdn-cgi/trace"),
    ("GeoJS", "https://get.geojs.io/v1/ip/geo.json"),
    ("ipinfo.io", "https://ipinfo.io/json"),
    ("ipwho.is", "https://ipwho.is/"),
    ("Country.is", "https://api.country.is/"),
    ("ifconfig.co", "https://ifconfig.co/json"),
)


def validate_source(source):
    expected = APPROVED_SOURCES.get(source.get("url"))
    if expected is None:
        raise ValueError("Для проверки IP разрешены только утверждённые зарубежные GeoIP API")
    if any(source.get(key) != value for key, value in expected.items()):
        raise ValueError("Параметры ответа источника не соответствуют утверждённому API")
