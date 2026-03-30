from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from collections import defaultdict
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))
from src.analyzer.detector import Detector

trafico = defaultdict(list)
detector = Detector(ventana_segundos=60)
contador = 0

def procesar_paquete(pkt):
    global contador

    if not pkt.haslayer(IP):
        return

    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    timestamp = datetime.now().strftime("%H:%M:%S")

    if pkt.haslayer(TCP):
        proto = "TCP"
        puerto = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        puerto = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        puerto = "-"
    else:
        proto = "OTRO"
        puerto = "-"

    trafico[ip_src].append({
        "timestamp": timestamp,
        "dst": ip_dst,
        "proto": proto,
        "puerto": puerto
    })

    print(f"[{timestamp}] {proto:5} | {ip_src:20} → {ip_dst:20} | puerto dst: {puerto}")

    # Resumen cada 10 paquetes
    total = sum(len(v) for v in trafico.values())
    if total % 10 == 0:
        print(f"\n--- Resumen: {len(trafico)} IPs únicas, {total} paquetes capturados ---\n")

    # Análisis de anomalías cada 5 paquetes
    contador += 1
    if contador % 5 == 0:
        alertas = detector.analizar(trafico)
        if alertas:
            print("\n" + "="*60)
            for alerta in alertas:
                print(f"⚠  ALERTA [{alerta['severidad']}] — {alerta['tipo']}")
                print(f"   IP:      {alerta['ip_src']}")
                print(f"   Detalle: {alerta['detalle']}")
            print("="*60 + "\n")

print("NetGuard v0.2 — captura + detección activa en eth0...\n")

sniff(
    iface="eth0",
    prn=procesar_paquete,
    store=False
)