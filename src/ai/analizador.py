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
        self.model = "claude-haiku-4-5-20251001"  # más barato y rápido para alertas

    def analizar_alerta(self, alerta, contexto_trafico=None):
        """Manda una alerta a Claude y recibe análisis en lenguaje natural."""

        # Construimos el prompt con el contexto de la alerta
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

        prompt += """
Respondé en español con este formato exacto:

ANÁLISIS: (1-2 oraciones explicando qué significa esta alerta)
RIESGO: (qué podría estar intentando hacer el atacante)
ACCIÓN: (2-3 pasos concretos y específicos para responder)
FALSO POSITIVO: (¿podría ser tráfico legítimo? ¿por qué sí o no?)
"""

        respuesta = self.client.messages.create(
            model=self.model,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )

        return respuesta.content[0].text