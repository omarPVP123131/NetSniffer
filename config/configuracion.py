"""
config/configuracion.py
─────────────────────────────────────────────────────────────────────────────
Almacena toda la configuración de la sesión en un único objeto inmutable.
Ventaja: evita variables globales dispersas y facilita pasar configuración
entre módulos sin acoplamientos innecesarios.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Configuracion:
    """Parámetros de configuración de la sesión de captura."""

    # ── Red ──────────────────────────────────────────────────────────────────
    interfaz: Optional[str] = None          # Ninguna = detección automática
    protocolo: str = "todos"                # tcp | udp | icmp | todos

    # ── Filtros de red ───────────────────────────────────────────────────────
    ip_origen: Optional[str] = None
    ip_destino: Optional[str] = None
    puerto: Optional[int] = None

    # ── Control de captura ───────────────────────────────────────────────────
    limite: int = 0                         # 0 = sin límite

    # ── Salida ───────────────────────────────────────────────────────────────
    archivo_salida: Optional[str] = None
    sin_color: bool = False
    modo_silencioso: bool = False

    # ── Interno ──────────────────────────────────────────────────────────────
    version: str = field(default="1.0.0", init=False)
