"""
parsers/protocolos.py
─────────────────────────────────────────────────────────────────────────────
Colección de funciones de desempaquetado para cada protocolo de red.

Organización:
  - PaqueteIP     → dataclass con los campos del encabezado IPv4
  - PaqueteTCP    → dataclass con los campos del encabezado TCP
  - PaqueteUDP    → dataclass con los campos del encabezado UDP
  - PaqueteICMP   → dataclass con los campos del encabezado ICMP
  - parsear_ip    → función principal que delega al parser correcto
  - NOMBRES_PROTO → diccionario de número → nombre legible

El uso de dataclasses facilita añadir nuevos protocolos: basta crear la
dataclass correspondiente y registrarla en `parsear_ip`.
"""

import socket
import struct
from dataclasses import dataclass, field
from typing import Optional


# ────────────────────────────────────────────────────────────────────────────
# Mapeo de número de protocolo → nombre legible
# ────────────────────────────────────────────────────────────────────────────
NOMBRES_PROTO: dict[int, str] = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}


def nombre_protocolo(numero: int) -> str:
    """Devuelve el nombre del protocolo o 'PROTO-<N>' si es desconocido."""
    return NOMBRES_PROTO.get(numero, f"PROTO-{numero}")


# ────────────────────────────────────────────────────────────────────────────
# Dataclasses de paquetes
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class PaqueteIP:
    """Encabezado IPv4 desempaquetado."""
    version: int
    longitud_encabezado: int    # en bytes
    ttl: int
    protocolo_num: int
    protocolo_nombre: str
    ip_origen: str
    ip_destino: str
    tamano_total: int           # bytes del paquete completo (incluye payload)
    # Payload del nivel de transporte (sin encabezado IP)
    datos_transporte: bytes = field(repr=False, default=b"")
    # Opcional: paquete de capa superior parseado
    transporte: Optional[object] = field(repr=False, default=None)


@dataclass
class PaqueteTCP:
    """Encabezado TCP desempaquetado."""
    puerto_origen: int
    puerto_destino: int
    numero_secuencia: int
    numero_ack: int
    longitud_encabezado: int    # en bytes
    # Flags como booleanos individuales para facilitar filtrado
    flag_urg: bool
    flag_ack: bool
    flag_psh: bool
    flag_rst: bool
    flag_syn: bool
    flag_fin: bool
    tamano_ventana: int
    payload: bytes = field(repr=False, default=b"")

    @property
    def flags_str(self) -> str:
        """Representación compacta de los flags activos (ej: SYN ACK)."""
        activos = []
        if self.flag_syn: activos.append("SYN")
        if self.flag_ack: activos.append("ACK")
        if self.flag_fin: activos.append("FIN")
        if self.flag_rst: activos.append("RST")
        if self.flag_psh: activos.append("PSH")
        if self.flag_urg: activos.append("URG")
        return " ".join(activos) if activos else "—"


@dataclass
class PaqueteUDP:
    """Encabezado UDP desempaquetado."""
    puerto_origen: int
    puerto_destino: int
    longitud: int               # longitud UDP (encabezado + datos)
    payload: bytes = field(repr=False, default=b"")


@dataclass
class PaqueteICMP:
    """Encabezado ICMP desempaquetado."""
    tipo: int
    codigo: int
    checksum: int
    descripcion: str = ""
    payload: bytes = field(repr=False, default=b"")


# ────────────────────────────────────────────────────────────────────────────
# Parsers individuales
# ────────────────────────────────────────────────────────────────────────────

def _parsear_tcp(datos: bytes) -> Optional[PaqueteTCP]:
    """Desempaqueta un encabezado TCP desde `datos`."""
    if len(datos) < 20:
        return None
    try:
        campos = struct.unpack("!HHLLBBHHH", datos[:20])
        longitud_enc = ((campos[4] >> 4) & 0xF) * 4
        flags_byte   = campos[5]
        return PaqueteTCP(
            puerto_origen      = campos[0],
            puerto_destino     = campos[1],
            numero_secuencia   = campos[2],
            numero_ack         = campos[3],
            longitud_encabezado= longitud_enc,
            flag_urg = bool(flags_byte & 0x20),
            flag_ack = bool(flags_byte & 0x10),
            flag_psh = bool(flags_byte & 0x08),
            flag_rst = bool(flags_byte & 0x04),
            flag_syn = bool(flags_byte & 0x02),
            flag_fin = bool(flags_byte & 0x01),
            tamano_ventana     = campos[7],
            payload            = datos[longitud_enc:],
        )
    except struct.error:
        return None


def _parsear_udp(datos: bytes) -> Optional[PaqueteUDP]:
    """Desempaqueta un encabezado UDP desde `datos`."""
    if len(datos) < 8:
        return None
    try:
        campos = struct.unpack("!HHHH", datos[:8])
        return PaqueteUDP(
            puerto_origen  = campos[0],
            puerto_destino = campos[1],
            longitud       = campos[2],
            payload        = datos[8:],
        )
    except struct.error:
        return None


# Tabla de descripciones ICMP tipo→código→descripción
_ICMP_DESC: dict[int, dict[int, str]] = {
    0:  {0: "Echo Reply"},
    3:  {
        0: "Destino de red inalcanzable",
        1: "Destino de host inalcanzable",
        3: "Puerto de destino inalcanzable",
    },
    8:  {0: "Echo Request (ping)"},
    11: {0: "TTL expirado en tránsito", 1: "TTL expirado en reensamblaje"},
}


def _parsear_icmp(datos: bytes) -> Optional[PaqueteICMP]:
    """Desempaqueta un encabezado ICMP desde `datos`."""
    if len(datos) < 4:
        return None
    try:
        tipo, codigo, checksum = struct.unpack("!BBH", datos[:4])
        desc = _ICMP_DESC.get(tipo, {}).get(codigo, f"Tipo {tipo} / Código {codigo}")
        return PaqueteICMP(
            tipo=tipo, codigo=codigo, checksum=checksum,
            descripcion=desc, payload=datos[4:],
        )
    except struct.error:
        return None


# ────────────────────────────────────────────────────────────────────────────
# Parser principal IPv4
# ────────────────────────────────────────────────────────────────────────────

def parsear_ip(datos_crudos: bytes) -> Optional[PaqueteIP]:
    """
    Parsea un paquete IPv4 completo.

    Parámetros
    ----------
    datos_crudos : bytes
        Bytes del paquete a partir del inicio del encabezado IP
        (sin encabezado Ethernet).

    Devuelve
    --------
    PaqueteIP con los campos del encabezado y, si el protocolo es TCP/UDP/ICMP,
    el campo `transporte` con el paquete de capa superior ya parseado.
    Devuelve None si los datos son insuficientes o malformados.
    """
    if len(datos_crudos) < 20:
        return None

    try:
        ip_raw = datos_crudos[:20]
        campos = struct.unpack("!BBHHHBBH4s4s", ip_raw)

        version_ihl      = campos[0]
        version          = version_ihl >> 4
        longitud_enc     = (version_ihl & 0x0F) * 4
        tamano_total     = campos[2]
        ttl              = campos[5]
        protocolo_num    = campos[6]
        ip_origen        = socket.inet_ntoa(campos[8])
        ip_destino       = socket.inet_ntoa(campos[9])

        datos_transporte = datos_crudos[longitud_enc:]

        # Parsear protocolo de transporte
        transporte = None
        if   protocolo_num == 6:   transporte = _parsear_tcp(datos_transporte)
        elif protocolo_num == 17:  transporte = _parsear_udp(datos_transporte)
        elif protocolo_num == 1:   transporte = _parsear_icmp(datos_transporte)

        return PaqueteIP(
            version            = version,
            longitud_encabezado= longitud_enc,
            ttl                = ttl,
            protocolo_num      = protocolo_num,
            protocolo_nombre   = nombre_protocolo(protocolo_num),
            ip_origen          = ip_origen,
            ip_destino         = ip_destino,
            tamano_total       = tamano_total,
            datos_transporte   = datos_transporte,
            transporte         = transporte,
        )
    except (struct.error, socket.error):
        return None
