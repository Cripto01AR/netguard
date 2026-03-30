from datetime import datetime, timedelta
from collections import defaultdict

class Detector:
    def __init__(self, ventana_segundos=60):
        self.ventana = timedelta(seconds=ventana_segundos)
        self.umbral_port_scan = 8
        self.umbral_fuerza_bruta = 5
        self.alertas_emitidas = set()

    def _paquetes_en_ventana(self, paquetes):
        ahora = datetime.now()
        recientes = []
        for p in paquetes:
            try:
                ts = datetime.strptime(p["timestamp"], "%H:%M:%S").replace(
                    year=ahora.year, month=ahora.month, day=ahora.day
                )
                diff = (ahora - ts).total_seconds()
                if 0 <= diff <= self.ventana.seconds:
                    recientes.append(p)
            except Exception:
                pass
        return recientes

    def detectar_port_scan(self, ip_src, paquetes):
        recientes = self._paquetes_en_ventana(paquetes)

        puertos_distintos = set(
            p["puerto"] for p in recientes
            if p["puerto"] != "-"
        )
        if len(puertos_distintos) >= self.umbral_port_scan:
            clave = f"portscan_{ip_src}"
            if clave not in self.alertas_emitidas:
                self.alertas_emitidas.add(clave)
                return {
                    "tipo": "PORT_SCAN",
                    "ip_src": ip_src,
                    "detalle": f"{len(puertos_distintos)} puertos distintos en {self.ventana.seconds}s",
                    "puertos": sorted(puertos_distintos),
                    "severidad": "ALTA"
                }
        return None

    def detectar_fuerza_bruta(self, ip_src, paquetes):
        recientes = self._paquetes_en_ventana(paquetes)

        conteo_por_puerto = defaultdict(int)
        for p in recientes:
            if p["proto"] == "TCP":
                conteo_por_puerto[p["puerto"]] += 1

        for puerto, conteo in conteo_por_puerto.items():
            if conteo >= self.umbral_fuerza_bruta:
                clave = f"bruteforce_{ip_src}_{puerto}"
                if clave not in self.alertas_emitidas:
                    self.alertas_emitidas.add(clave)

                    servicios = {22: "SSH", 21: "FTP", 3389: "RDP", 80: "HTTP", 443: "HTTPS"}
                    servicio = servicios.get(puerto, f"puerto {puerto}")

                    return {
                        "tipo": "FUERZA_BRUTA",
                        "ip_src": ip_src,
                        "detalle": f"{conteo} conexiones a {servicio} en {self.ventana.seconds}s",
                        "puerto": puerto,
                        "severidad": "ALTA" if puerto == 22 else "MEDIA"
                    }
        return None

    def analizar(self, trafico):
        alertas = []

        for ip_src, paquetes in trafico.items():
            if False:  # desactivado para testing
                continue

            alerta_scan = self.detectar_port_scan(ip_src, paquetes)
            if alerta_scan:
                alertas.append(alerta_scan)

            alerta_bruta = self.detectar_fuerza_bruta(ip_src, paquetes)
            if alerta_bruta:
                alertas.append(alerta_bruta)

        return alertas