# src/analyzer/geolocalizacion.py
import requests
import time
from functools import lru_cache

# IPs privadas que no tienen geolocalización
IPS_PRIVADAS = [
    "127.", "10.", "192.168.", "172.16.", "172.17.",
    "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
    "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.", "0.0.0.0"
]

def es_ip_privada(ip: str) -> bool:
    return any(ip.startswith(prefijo) for prefijo in IPS_PRIVADAS)

@lru_cache(maxsize=512)
def geolocalizacion(ip: str) -> dict:
    """
    Consulta la geolocalización de una IP.
    lru_cache cachea los resultados — si la misma IP aparece varias veces
    no hacemos múltiples requests a la API.
    """
    if es_ip_privada(ip):
        return {
            "ip": ip,
            "pais": "Red local",
            "pais_codigo": "LAN",
            "ciudad": "—",
            "isp": "—",
            "org": "—",
            "lat": 0,
            "lon": 0,
            "es_privada": True
        }

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=3  # no bloqueamos más de 3 segundos
        )
        data = response.json()

        if data.get("status") == "success":
            return {
                "ip": ip,
                "pais": data.get("country", "Desconocido"),
                "pais_codigo": data.get("countryCode", "??"),
                "ciudad": data.get("city", "—"),
                "isp": data.get("isp", "—"),
                "org": data.get("org", "—"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "es_privada": False
            }
    except Exception:
        pass

    return {
        "ip": ip,
        "pais": "Desconocido",
        "pais_codigo": "??",
        "ciudad": "—",
        "isp": "—",
        "org": "—",
        "lat": 0,
        "lon": 0,
        "es_privada": False
    }