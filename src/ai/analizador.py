# src/ai/analizador.py
import os
import anthropic
from dotenv import load_dotenv

load_dotenv()

class AnalizadorIA:
    def __init__(self):
        self.client = anthropic.Anthropic(
            api_key=os.getenv('ANTHROPIC_API_KEY')
        )
        self.model = "claude-haiku-4-5-20251001"

    def analizar_alerta(self, alerta, puertos_abiertos=None):
        """Manda una alerta a Claude con contexto adicional del scanner."""

        prompt = f"""Sos un analista de seguridad de redes. Recibiste esta alerta de NetGuard:

TIPO: {alerta['tipo']}
IP ORIGEN: {alerta['ip_src']}
SEVERIDAD: {alerta['severidad']}
DETALLE: {alerta['detalle']}
"""
        if alerta['tipo'] == 'PORT_SCAN' and 'puertos' in alerta:
            servicios = {
                22: "SSH", 80: "HTTP", 443: "HTTPS",
                21: "FTP", 25: "SMTP", 110: "POP3",
                143: "IMAP", 3306: "MySQL", 5432: "PostgreSQL",
                3389: "RDP", 8080: "HTTP-alt"
            }
            puertos_detalle = [
                f"{p} ({servicios.get(p, 'desconocido')})"
                for p in alerta['puertos']
            ]
            prompt += f"PUERTOS ESCANEADOS: {', '.join(puertos_detalle)}\n"

        # Si tenemos resultados del scanner, los agregamos al contexto
        if puertos_abiertos:
            prompt += f"\nCONTRA-SCAN DE LA IP ATACANTE ({alerta['ip_src']}):\n"
            if puertos_abiertos:
                for p in puertos_abiertos:
                    prompt += f"  - Puerto {p['puerto']} ({p['servicio']}) ABIERTO — latencia {p['latencia_ms']}ms\n"
                prompt += "\nEsto significa que la IP atacante también tiene servicios expuestos.\n"
            else:
                prompt += "  No se encontraron puertos abiertos en la IP atacante.\n"

        prompt += """
Respondé en español con este formato exacto:

ANÁLISIS: (1-2 oraciones explicando qué significa esta alerta)
RIESGO: (qué podría estar intentando hacer el atacante)
ACCIÓN: (2-3 pasos concretos y específicos para responder)
FALSO POSITIVO: (¿podría ser tráfico legítimo? ¿por qué sí o no?)
"""
        if puertos_abiertos:
            prompt += "PERFIL ATACANTE: (qué dice el contra-scan sobre el origen del ataque)\n"

        respuesta = self.client.messages.create(
            model=self.model,
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        return respuesta.content[0].text