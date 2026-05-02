"""
salida/escritor.py
─────────────────────────────────────────────────────────────────────────────
Escritura opcional de paquetes a disco en formato TXT o CSV.

Diseño:
  - EscritorBase  → interfaz abstracta (método `escribir` y `cerrar`)
  - EscritorTXT   → formato legible, separado por líneas
  - EscritorCSV   → formato tabular, importable en Excel / pandas
  - crear_escritor → factory que devuelve el escritor correcto según extensión

Para añadir un nuevo formato (ej: JSON, PCAP-texto) basta con crear una
nueva subclase de EscritorBase y registrarla en `crear_escritor`.
"""

import csv
import os
import time
from abc import ABC, abstractmethod
from typing import Optional

from parsers.protocolos import PaqueteIP, PaqueteTCP, PaqueteUDP, PaqueteICMP


# ────────────────────────────────────────────────────────────────────────────
# Interfaz base
# ────────────────────────────────────────────────────────────────────────────

class EscritorBase(ABC):
    """Interfaz que deben implementar todos los escritores de salida."""

    @abstractmethod
    def escribir(self, paquete: PaqueteIP, numero: int):
        """Escribe los datos de un paquete en el destino."""
        ...

    @abstractmethod
    def cerrar(self):
        """Libera recursos (cierra archivo, etc.)."""
        ...


# ────────────────────────────────────────────────────────────────────────────
# Escritor TXT
# ────────────────────────────────────────────────────────────────────────────

class EscritorTXT(EscritorBase):
    """Escribe paquetes en formato de texto legible."""

    CABECERA = (
        "╔══════════════════════════════════════════════════════╗\n"
        "║   NetSniffer — Registro de captura                  ║\n"
        "╚══════════════════════════════════════════════════════╝\n"
    )

    def __init__(self, ruta: str):
        self._archivo = open(ruta, "w", encoding="utf-8")
        self._archivo.write(self.CABECERA)
        self._archivo.write(f"Inicio: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    def escribir(self, paquete: PaqueteIP, numero: int):
        hora = time.strftime("%H:%M:%S")
        linea = (
            f"[{numero:>5}] {hora}  "
            f"{paquete.ip_origen:<18} → {paquete.ip_destino:<18}  "
            f"{paquete.protocolo_nombre:<6}  "
            f"{_info_transporte_txt(paquete)}\n"
        )
        self._archivo.write(linea)
        self._archivo.flush()

    def cerrar(self):
        self._archivo.write(f"\nFin: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._archivo.close()


# ────────────────────────────────────────────────────────────────────────────
# Escritor CSV
# ────────────────────────────────────────────────────────────────────────────

_COLUMNAS_CSV = [
    "num", "hora", "ip_origen", "ip_destino", "protocolo",
    "puerto_origen", "puerto_destino", "ttl", "tamano_bytes", "info",
]


class EscritorCSV(EscritorBase):
    """Escribe paquetes en formato CSV importable en Excel / pandas."""

    def __init__(self, ruta: str):
        self._archivo = open(ruta, "w", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._archivo, fieldnames=_COLUMNAS_CSV)
        self._writer.writeheader()

    def escribir(self, paquete: PaqueteIP, numero: int):
        pto_orig, pto_dest = _puertos(paquete)
        self._writer.writerow({
            "num":           numero,
            "hora":          time.strftime("%H:%M:%S"),
            "ip_origen":     paquete.ip_origen,
            "ip_destino":    paquete.ip_destino,
            "protocolo":     paquete.protocolo_nombre,
            "puerto_origen": pto_orig,
            "puerto_destino":pto_dest,
            "ttl":           paquete.ttl,
            "tamano_bytes":  paquete.tamano_total,
            "info":          _info_transporte_txt(paquete),
        })
        self._archivo.flush()

    def cerrar(self):
        self._archivo.close()


# ────────────────────────────────────────────────────────────────────────────
# Factory
# ────────────────────────────────────────────────────────────────────────────

def crear_escritor(ruta: Optional[str]) -> Optional[EscritorBase]:
    """
    Crea el escritor adecuado según la extensión del archivo.
    Devuelve None si `ruta` es None (sin salida a disco).
    """
    if not ruta:
        return None

    ext = os.path.splitext(ruta)[1].lower()
    if ext == ".csv":
        return EscritorCSV(ruta)
    else:
        # Por defecto: TXT (también para .txt, .log, u otras extensiones)
        return EscritorTXT(ruta)


# ────────────────────────────────────────────────────────────────────────────
# Helpers internos
# ────────────────────────────────────────────────────────────────────────────

def _puertos(paquete: PaqueteIP) -> tuple:
    t = paquete.transporte
    if isinstance(t, (PaqueteTCP, PaqueteUDP)):
        return t.puerto_origen, t.puerto_destino
    return "", ""


def _info_transporte_txt(paquete: PaqueteIP) -> str:
    t = paquete.transporte
    if isinstance(t, PaqueteTCP):
        return f":{t.puerto_origen}→:{t.puerto_destino} [{t.flags_str}]"
    if isinstance(t, PaqueteUDP):
        return f":{t.puerto_origen}→:{t.puerto_destino} len={t.longitud}"
    if isinstance(t, PaqueteICMP):
        return f"{t.descripcion}"
    return f"TTL={paquete.ttl}"
