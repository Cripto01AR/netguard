# src/dashboard/app.py
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from collections import defaultdict
import asyncio
import json
import threading
from datetime import datetime

from src.analyzer.geolocalizacion import geolocalizacion
from src.analyzer.scanner_integration import escanear_ip
from src.capture.sniffer_rs import iniciar_captura_rust
from src.analyzer.detector import Detector
from src.ai.analizador import AnalizadorIA

app = FastAPI()

# Estado global compartido entre el sniffer y el dashboard
estado = {
    "trafico": defaultdict(list),
    "alertas": [],
    "paquetes_recientes": [],  # últimos 50 paquetes para mostrar en vivo
    "stats": {
        "total_paquetes": 0,
        "ips_unicas": 0,
        "alertas_total": 0
    }
}

detector = Detector(ventana_segundos=60)
analizador_ia = AnalizadorIA()

# Lista de clientes WebSocket conectados
clientes_ws = []

# ── Captura de paquetes ──────────────────────────────────────────

def iniciar_sniffer():
    def adaptar(pkt):
        # El módulo Rust ya parsea el paquete — lo adaptamos al formato interno
        procesar_paquete_rust(pkt)
    iniciar_captura_rust(adaptar)

def procesar_paquete_rust(pkt):
    """Procesa paquetes que vienen del módulo Rust (ya parseados como dict)."""
    ip_src   = pkt["src"]
    ip_dst   = pkt["dst"]
    timestamp = pkt["timestamp"]
    proto    = pkt["protocolo"]
    puerto   = pkt["puerto_dst"]

    estado["trafico"][ip_src].append({
        "timestamp": timestamp,
        "dst": ip_dst,
        "proto": proto,
        "puerto": puerto
    })

    paquete = {
        "timestamp": timestamp,
        "src": ip_src,
        "dst": ip_dst,
        "proto": proto,
        "puerto": puerto
    }

    estado["paquetes_recientes"].append(paquete)
    if len(estado["paquetes_recientes"]) > 50:
        estado["paquetes_recientes"].pop(0)

    estado["stats"]["total_paquetes"] += 1
    estado["stats"]["ips_unicas"] = len(estado["trafico"])

# ── Loop de análisis ─────────────────────────────────────────────

def loop_analisis():
    while True:
        import time
        time.sleep(10)
        alertas = detector.analizar(estado["trafico"])
        for alerta in alertas:
            print(f"⚠ ALERTA: {alerta['tipo']} desde {alerta['ip_src']}")
            
            # Geolocalización de la IP atacante
            geo = geolocalizacion(alerta['ip_src'])
            alerta['geo'] = geo
            print(f"   📍 {geo['ciudad']}, {geo['pais']} — {geo['isp']}")
            puertos_abiertos = None

            # Si es un port scan, contra-escaneamos la IP atacante
            if alerta['tipo'] == 'PORT_SCAN':
                print(f"🔍 Contra-escaneando {alerta['ip_src']}...")
                puertos_abiertos = escanear_ip(
                    alerta['ip_src'],
                    ports_start=1,
                    ports_end=1024,
                    timeout_ms=1500
                )
                print(f"   {len(puertos_abiertos)} puertos abiertos encontrados")

            analisis = analizador_ia.analizar_alerta(alerta, puertos_abiertos)
            alerta["analisis_ia"] = analisis
            alerta["timestamp"] = datetime.now().strftime("%H:%M:%S")

            # Agregamos info del contra-scan a la alerta para el dashboard
            if puertos_abiertos is not None:
                alerta["contra_scan"] = puertos_abiertos

            estado["alertas"].insert(0, alerta)
            estado["stats"]["alertas_total"] += 1

            asyncio.run(broadcast({
                "tipo": "alerta",
                "data": alerta
            }))

# ── WebSocket ────────────────────────────────────────────────────

async def broadcast(mensaje):
    """Manda un mensaje a todos los clientes conectados."""
    desconectados = []
    for ws in clientes_ws:
        try:
            await ws.send_text(json.dumps(mensaje))
        except Exception:
            desconectados.append(ws)
    for ws in desconectados:
        clientes_ws.remove(ws)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clientes_ws.append(websocket)
    try:
        # Mandamos el estado actual al cliente que se conecta
        await websocket.send_text(json.dumps({
            "tipo": "estado_inicial",
            "data": {
                "paquetes_recientes": estado["paquetes_recientes"],
                "alertas": estado["alertas"][-10:],
                "stats": estado["stats"]
            }
        }))

        # Loop de actualizaciones de stats y tráfico cada 2 segundos
        while True:
            await asyncio.sleep(2)
            await websocket.send_text(json.dumps({
                "tipo": "actualizacion",
                "data": {
                    "paquetes_recientes": estado["paquetes_recientes"][-10:],
                    "stats": estado["stats"]
                }
            }))
    except WebSocketDisconnect:
        clientes_ws.remove(websocket)

# ── Startup ──────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    # Lanzamos sniffer y detector en threads separados
    threading.Thread(target=iniciar_sniffer, daemon=True).start()
    threading.Thread(target=loop_analisis, daemon=True).start()
    print("NetGuard dashboard iniciado en http://localhost:8000")

# ── Rutas HTTP ───────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="src/dashboard/static"), name="static")

@app.get("/")
async def root():
    with open("src/dashboard/static/index.html") as f:
        return HTMLResponse(f.read())

@app.get("/api/stats")
async def get_stats():
    return estado["stats"]

@app.get("/api/alertas")
async def get_alertas():
    return estado["alertas"]