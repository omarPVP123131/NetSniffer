"""
estadisticas/monitor.py
─────────────────────────────────────────────────────────────────────────────
Recopila estadísticas en tiempo real de los paquetes capturados.

Métricas disponibles:
  - Contador total de paquetes
  - Contadores por protocolo
  - Top-5 IPs de origen y destino más activas
  - Bytes totales capturados
  - Duración de la sesión

El Monitor es independiente del resto: recibe PaqueteIP y actualiza
sus contadores internos. No sabe nada de la UI ni del sniffer.
"""

import time
from collections import defaultdict, Counter
from parsers.protocolos import PaqueteIP


class Monitor:
    """Acumulador de estadísticas de sesión."""

    def __init__(self):
        self.inicio: float = time.time()
        self.total: int = 0
        self.bytes_totales: int = 0
        self.por_protocolo: Counter = Counter()
        self.ips_origen: Counter = Counter()
        self.ips_destino: Counter = Counter()
        self.por_puerto: Counter = Counter()        # TCP/UDP únicamente

    # ── API pública ──────────────────────────────────────────────────────────

    def registrar(self, paquete: PaqueteIP):
        """Actualiza todos los contadores con los datos del paquete."""
        self.total += 1
        self.bytes_totales += paquete.tamano_total
        self.por_protocolo[paquete.protocolo_nombre] += 1
        self.ips_origen[paquete.ip_origen] += 1
        self.ips_destino[paquete.ip_destino] += 1

        # Estadísticas de puerto (solo TCP/UDP)
        from parsers.protocolos import PaqueteTCP, PaqueteUDP
        t = paquete.transporte
        if isinstance(t, (PaqueteTCP, PaqueteUDP)):
            self.por_puerto[t.puerto_destino] += 1

    @property
    def duracion(self) -> float:
        """Segundos desde el inicio de la captura."""
        return time.time() - self.inicio

    @property
    def pps(self) -> float:
        """Paquetes por segundo promedio."""
        d = self.duracion
        return self.total / d if d > 0 else 0.0

    @property
    def bps(self) -> float:
        """Bytes por segundo promedio."""
        d = self.duracion
        return self.bytes_totales / d if d > 0 else 0.0

    def top_ips_origen(self, n: int = 5) -> list[tuple[str, int]]:
        return self.ips_origen.most_common(n)

    def top_ips_destino(self, n: int = 5) -> list[tuple[str, int]]:
        return self.ips_destino.most_common(n)

    def top_puertos(self, n: int = 5) -> list[tuple[int, int]]:
        return self.por_puerto.most_common(n)
