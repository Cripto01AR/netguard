# src/capture/sniffer_rs.py
import subprocess
import json
import os
import sys
from collections import defaultdict

# Ruta al binario compilado de Rust
BINARY = os.path.join(
    os.path.dirname(__file__),
    "../../capture_rs/target/release/capture_rs"
)

def iniciar_captura_rust(callback):
    """
    Lanza el binario Rust y procesa su output línea por línea.
    Por cada paquete válido llama a callback(paquete).
    """
    if not os.path.exists(BINARY):
        print(f"Error: binario no encontrado en {BINARY}")
        print("Ejecutá: cd capture_rs && cargo build --release")
        sys.exit(1)

    print(f"Iniciando captura con módulo Rust...")

    # Lanzamos el proceso Rust — su stdout es nuestro stdin
    proceso = subprocess.Popen(
        [BINARY],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1  # line buffered — procesamos línea por línea
    )

    try:
        for linea in proceso.stdout:
            linea = linea.strip()
            if not linea:
                continue
            try:
                paquete = json.loads(linea)
                callback(paquete)
            except json.JSONDecodeError:
                continue  # ignoramos líneas malformadas
    except KeyboardInterrupt:
        proceso.terminate()

if __name__ == "__main__":
    # Test directo — mostramos paquetes en consola
    def mostrar(pkt):
        print(f"[{pkt['timestamp']}] {pkt['protocolo']:5} | "
              f"{pkt['src']:20} → {pkt['dst']:20} | "
              f"puerto: {pkt['puerto_dst']}")

    iniciar_captura_rust(mostrar)