# src/analyzer/scanner_integration.py
import subprocess
import json
import os

SCANNER_BINARY = os.path.join(
    os.path.dirname(__file__),
    "../../vuln_scanner/target/release/vuln_scanner"
)

def escanear_ip(ip: str, ports_start: int = 1, ports_end: int = 1024, timeout_ms: int = 1500) -> list:
    """
    Lanza el scanner Rust contra una IP y retorna los puertos abiertos.
    Se usa cuando se detecta una IP sospechosa.
    """
    if not os.path.exists(SCANNER_BINARY):
        print(f"Scanner binary no encontrado en {SCANNER_BINARY}")
        return []

    try:
        resultado = subprocess.run(
            [
                SCANNER_BINARY,
                "--host", ip,
                "--start", str(ports_start),
                "--end", str(ports_end),
                "--timeout", str(timeout_ms),
                "--concurrencia", "200"
            ],
            capture_output=True,
            text=True,
            timeout=60  # máximo 60 segundos para el scan completo
        )

        # El output tiene texto y JSON — extraemos solo el JSON
        output = resultado.stdout
        if "--- JSON ---" in output:
            json_parte = output.split("--- JSON ---")[1].strip()
            return json.loads(json_parte)
        return []

    except subprocess.TimeoutExpired:
        print(f"Timeout escaneando {ip}")
        return []
    except Exception as e:
        print(f"Error escaneando {ip}: {e}")
        return []