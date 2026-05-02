"""
filtros/motor.py
─────────────────────────────────────────────────────────────────────────────
Motor de filtros: decide si un paquete parseado debe ser procesado o ignorado.

Diseño:
  - Cada regla de filtrado es un método privado `_filtro_*`.
  - `aceptar(paquete)` ejecuta todos los filtros activos en cadena.
  - Agregar un nuevo filtro = añadir un método y llamarlo en `aceptar`.

Esto hace que el motor sea fácilmente extensible sin modificar el resto del
código (principio Open/Closed).
"""

from config.configuracion import Configuracion
from parsers.protocolos import PaqueteIP, PaqueteTCP, PaqueteUDP


class MotorFiltros:
    """Aplica los filtros configurados a cada paquete capturado."""

    def __init__(self, config: Configuracion):
        self._config = config

    # ── API pública ──────────────────────────────────────────────────────────

    def aceptar(self, paquete: PaqueteIP) -> bool:
        """
        Devuelve True si el paquete pasa TODOS los filtros activos.
        El orden importa: los filtros más baratos van primero.
        """
        return (
            self._filtro_protocolo(paquete)
            and self._filtro_ip_origen(paquete)
            and self._filtro_ip_destino(paquete)
            and self._filtro_puerto(paquete)
        )

    # ── Filtros individuales ─────────────────────────────────────────────────

    def _filtro_protocolo(self, paquete: PaqueteIP) -> bool:
        proto = self._config.protocolo
        if proto == "todos":
            return True
        return paquete.protocolo_nombre.lower() == proto.lower()

    def _filtro_ip_origen(self, paquete: PaqueteIP) -> bool:
        ip = self._config.ip_origen
        if not ip:
            return True
        return paquete.ip_origen == ip

    def _filtro_ip_destino(self, paquete: PaqueteIP) -> bool:
        ip = self._config.ip_destino
        if not ip:
            return True
        return paquete.ip_destino == ip

    def _filtro_puerto(self, paquete: PaqueteIP) -> bool:
        puerto = self._config.puerto
        if not puerto:
            return True
        t = paquete.transporte
        if isinstance(t, PaqueteTCP) or isinstance(t, PaqueteUDP):
            return t.puerto_origen == puerto or t.puerto_destino == puerto
        return False  # ICMP no tiene puertos

    # ── Resumen de filtros activos (para mostrar en UI) ──────────────────────

    def resumen(self) -> list[str]:
        """Devuelve lista de strings describiendo los filtros activos."""
        activos = []
        c = self._config
        if c.protocolo != "todos":
            activos.append(f"Protocolo = {c.protocolo.upper()}")
        if c.ip_origen:
            activos.append(f"IP origen  = {c.ip_origen}")
        if c.ip_destino:
            activos.append(f"IP destino = {c.ip_destino}")
        if c.puerto:
            activos.append(f"Puerto     = {c.puerto}")
        return activos if activos else ["Ninguno (capturando todo)"]
