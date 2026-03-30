# src/capture/sniffer.py
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from collections import defaultdict

# Estructura donde guardamos los paquetes capturados
# defaultdict(list) crea una lista vacía automáticamente para cada IP nueva
trafico = defaultdict(list)

def procesar_paquete(pkt):
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

    # Guardamos cada paquete asociado a su IP origen
    trafico[ip_src].append({
        "timestamp": timestamp,
        "dst": ip_dst,
        "proto": proto,
        "puerto": puerto
    })

    print(f"[{timestamp}] {proto:5} | {ip_src:20} → {ip_dst:20} | puerto dst: {puerto}")

    # Cada 10 paquetes mostramos un resumen
    total = sum(len(v) for v in trafico.values())
    if total % 10 == 0:
        print(f"\n--- Resumen: {len(trafico)} IPs únicas, {total} paquetes capturados ---\n")

print("NetGuard v0.1 — capturando en eth0... (Ctrl+C para detener)\n")

sniff(
    iface="eth0",
    prn=procesar_paquete,
    store=False
)