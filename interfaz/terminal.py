"""
interfaz/terminal.py
─────────────────────────────────────────────────────────────────────────────
Presentación visual completa con soporte de color para Windows, Linux y macOS.

PROBLEMA EN WINDOWS:
  La terminal de Windows (cmd.exe / PowerShell clásico) no procesa códigos
  ANSI de color a menos que se active el modo de procesamiento VT100.
  Windows Terminal y VS Code ya lo hacen, pero cmd.exe/PowerShell antiguos no.

SOLUCIÓN (en orden de prioridad):
  1. Windows 10+: activar VT100 vía ctypes (kernel32.SetConsoleMode)
     → funciona en cmd.exe, PowerShell, Windows Terminal sin dependencias
  2. Si falla: intentar importar colorama (pip install colorama)
     → funciona en versiones antiguas de Windows / servidores
  3. Si ninguno funciona: modo sin color automático (nunca falla)

CAPACIDADES DETECTADAS:
  La clase _DetectorTerminal revisa en tiempo de carga si la terminal soporta:
  - colores ANSI
  - caracteres Unicode extendidos (╔ ║ ═ █ ░ ▶ ✔ ✖)
  Si no soporta Unicode → usa ASCII de respaldo (=, |, -, >, *, X)
"""

import os
import sys
import time
from config.configuracion import Configuracion
from parsers.protocolos import PaqueteIP, PaqueteTCP, PaqueteUDP, PaqueteICMP
from estadisticas.monitor import Monitor


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 1 — Activación de color en Windows
# ════════════════════════════════════════════════════════════════════════════

def _activar_color_windows() -> bool:
    """
    Activa el procesamiento VT100 en la consola de Windows via ctypes.
    Devuelve True si tuvo éxito (Windows 10 build 1511+).
    """
    if os.name != "nt":
        return True

    try:
        import ctypes
        import ctypes.wintypes

        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        STD_OUTPUT_HANDLE = -11

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        if handle in (0, -1):
            return False

        modo_actual = ctypes.wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(modo_actual)):
            return False

        nuevo_modo = modo_actual.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, nuevo_modo))
    except Exception:
        return False


def _activar_colorama() -> bool:
    """Intenta usar colorama como fallback para Windows antiguo."""
    try:
        import colorama
        colorama.init(autoreset=False)
        return True
    except ImportError:
        return False


def _inicializar_color(sin_color: bool) -> bool:
    """
    Determina si los colores ANSI funcionarán en este entorno.
    Devuelve True si los colores están disponibles.
    """
    if sin_color:
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        return _activar_color_windows() or _activar_colorama()
    return True


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 2 — Detección de capacidades Unicode
# ════════════════════════════════════════════════════════════════════════════

def _soporta_unicode() -> bool:
    """
    Comprueba si la terminal puede renderizar caracteres Unicode extendidos.
    Windows con encoding cp850/cp1252 (cmd.exe viejo) usa ASCII de respaldo.
    """
    try:
        enc = sys.stdout.encoding or "ascii"
        "╔█░✔▶→".encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 3 — Paleta de colores ANSI
# ════════════════════════════════════════════════════════════════════════════

class _Colores:
    RESET    = "\033[0m"
    NEGRITA  = "\033[1m"
    DIM      = "\033[2m"
    BLANCO   = "\033[97m"
    GRIS     = "\033[90m"
    VERDE    = "\033[92m"
    AMARILLO = "\033[93m"
    AZUL     = "\033[94m"
    MAGENTA  = "\033[95m"
    CIAN     = "\033[96m"
    ROJO     = "\033[91m"
    NARANJA  = "\033[38;5;208m"


class _SinColor:
    def __getattr__(self, _): return ""


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 4 — Símbolos adaptativos (Unicode vs ASCII)
# ════════════════════════════════════════════════════════════════════════════

class _SimbolosUnicode:
    ESQ_SUP_IZQ = "╔"; ESQ_SUP_DER = "╗"
    ESQ_INF_IZQ = "╚"; ESQ_INF_DER = "╝"
    BORDE_H = "═"; BORDE_V = "║"
    LINEA_H = "─"; LINEA_H2 = "═"
    LLENO = "█"; VACIO = "░"
    OK = "✔"; ERR = "✖"; PLAY = "▶"
    FLECHA = "→"; PUNTO = "•"

class _SimbolosASCII:
    ESQ_SUP_IZQ = "+"; ESQ_SUP_DER = "+"
    ESQ_INF_IZQ = "+"; ESQ_INF_DER = "+"
    BORDE_H = "="; BORDE_V = "|"
    LINEA_H = "-"; LINEA_H2 = "="
    LLENO = "#"; VACIO = "."
    OK = "[OK]"; ERR = "[X]"; PLAY = ">"
    FLECHA = "->"; PUNTO = "*"


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 5 — Color por protocolo y flags TCP
# ════════════════════════════════════════════════════════════════════════════

def _color_protocolo(nombre: str, C) -> str:
    return {
        "TCP": C.AZUL, "UDP": C.VERDE, "ICMP": C.AMARILLO,
        "OSPF": C.MAGENTA, "SCTP": C.NARANJA, "ICMPv6": C.CIAN,
    }.get(nombre, C.GRIS)


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 6 — Clase principal Terminal
# ════════════════════════════════════════════════════════════════════════════

class Terminal:
    """
    Gestiona toda la presentación visual en la terminal.
    Detecta automáticamente las capacidades del entorno.
    """

    def __init__(self, config: Configuracion):
        self._config     = config
        self._colores_ok = _inicializar_color(config.sin_color)
        self._unicode_ok = _soporta_unicode() and not config.sin_color
        self.C  = _Colores()        if self._colores_ok else _SinColor()
        self.S  = _SimbolosUnicode() if self._unicode_ok else _SimbolosASCII()
        self._contador = 0

        if os.name == "nt" and not self._colores_ok and not config.sin_color:
            print("[!] Colores no disponibles en esta terminal.")
            print("    Usa Windows Terminal o: pip install colorama")
            print()

    # ── 6.1 Banner ───────────────────────────────────────────────────────────

    def mostrar_banner(self):
        C, S = self.C, self.S
        ancho  = 54
        borde  = S.BORDE_H * ancho
        titulo = f"NetSniffer v{self._config.version}".center(ancho)
        sub    = "Captura  |  Filtra  |  Analiza  |  IPv4".center(ancho)

        print()
        print(f"  {C.CIAN}{C.NEGRITA}{S.ESQ_SUP_IZQ}{borde}{S.ESQ_SUP_DER}{C.RESET}")
        print(f"  {C.CIAN}{C.NEGRITA}{S.BORDE_V}{C.RESET}{C.BLANCO}{C.NEGRITA}{titulo}{C.RESET}{C.CIAN}{C.NEGRITA}{S.BORDE_V}{C.RESET}")
        print(f"  {C.CIAN}{C.NEGRITA}{S.BORDE_V}{C.RESET}{C.GRIS}{sub}{C.RESET}{C.CIAN}{C.NEGRITA}{S.BORDE_V}{C.RESET}")
        print(f"  {C.CIAN}{C.NEGRITA}{S.ESQ_INF_IZQ}{borde}{S.ESQ_INF_DER}{C.RESET}")
        print()

        # Información del entorno
        so   = "Windows" if os.name == "nt" else ("macOS" if sys.platform == "darwin" else "Linux")
        modo = f"{C.VERDE}Color{C.RESET}"     if self._colores_ok else f"{C.GRIS}Sin color{C.RESET}"
        unc  = f"{C.VERDE}Unicode{C.RESET}"   if self._unicode_ok else f"{C.GRIS}ASCII{C.RESET}"
        print(f"  {C.GRIS}SO: {C.RESET}{C.AMARILLO}{so}{C.RESET}   Modo: {modo}   Charset: {unc}")
        print()

    # ── 6.2 Configuración activa ─────────────────────────────────────────────

    def mostrar_configuracion(self, config: Configuracion):
        C, S = self.C, self.S
        sep = S.LINEA_H * 56

        print(f"  {C.NEGRITA}Configuracion de sesion:{C.RESET}")
        print(f"  {C.GRIS}{sep}{C.RESET}")

        filas = [
            ("Protocolo",  config.protocolo.upper()),
            ("IP origen",  config.ip_origen  or "cualquiera"),
            ("IP destino", config.ip_destino or "cualquiera"),
            ("Puerto",     str(config.puerto) if config.puerto else "cualquiera"),
            ("Limite",     f"{config.limite} paquetes" if config.limite else "sin limite"),
            ("Salida",     config.archivo_salida or "solo pantalla"),
        ]
        for clave, valor in filas:
            print(f"  {C.CIAN}{S.PUNTO}{C.RESET} {C.GRIS}{clave:<12}{C.RESET}  {C.AMARILLO}{valor}{C.RESET}")

        print(f"  {C.GRIS}{sep}{C.RESET}")
        print(f"\n  {C.VERDE}{S.PLAY}  Captura iniciada {S.FLECHA} Ctrl+C para detener{C.RESET}\n")
        self._cabecera_tabla()

    def _cabecera_tabla(self):
        C, S = self.C, self.S
        cols = f"  {'N':<5} {'HORA':<10} {'ORIGEN':<18}   {'DESTINO':<18} {'PROTO':<6} INFO"
        sep  = S.LINEA_H * 84
        print(f"{C.GRIS}{C.NEGRITA}{cols}{C.RESET}")
        print(f"  {C.GRIS}{sep}{C.RESET}")

    # ── 6.3 Línea por paquete ────────────────────────────────────────────────

    def imprimir_paquete(self, paquete: PaqueteIP):
        if self._config.modo_silencioso:
            return

        C, S = self.C, self.S
        self._contador += 1
        hora = time.strftime("%H:%M:%S")

        badge  = f"{_color_protocolo(paquete.protocolo_nombre, C)}{C.NEGRITA}{paquete.protocolo_nombre:<5}{C.RESET}"
        info   = self._info_transporte(paquete)
        flecha = f"{C.GRIS}{S.FLECHA}{C.RESET}"

        # IP local = amarillo, externa = blanco, destino externo = rojo suave
        color_orig = C.AMARILLO if _es_local(paquete.ip_origen) else C.BLANCO
        color_dest = C.ROJO     if _es_externa(paquete.ip_destino) else C.BLANCO

        print(
            f"  {C.GRIS}{self._contador:<5}{C.RESET}"
            f"{C.DIM}{hora}{C.RESET}  "
            f"{color_orig}{paquete.ip_origen:<18}{C.RESET}"
            f"{flecha} "
            f"{color_dest}{paquete.ip_destino:<18}{C.RESET}"
            f"{badge}  "
            f"{C.GRIS}{info}{C.RESET}"
        )

    def _info_transporte(self, paquete: PaqueteIP) -> str:
        C, S = self.C, self.S
        t = paquete.transporte
        if isinstance(t, PaqueteTCP):
            color_f = self._color_flags_tcp(t)
            return (
                f":{t.puerto_origen} {S.FLECHA} :{t.puerto_destino}"
                f"  {color_f}[{t.flags_str}]{C.RESET}"
                f"  win={t.tamano_ventana}"
            )
        if isinstance(t, PaqueteUDP):
            return f":{t.puerto_origen} {S.FLECHA} :{t.puerto_destino}  len={t.longitud}"
        if isinstance(t, PaqueteICMP):
            return f"{t.descripcion}  (t={t.tipo} c={t.codigo})"
        return f"TTL={paquete.ttl}  tam={paquete.tamano_total}B"

    def _color_flags_tcp(self, tcp) -> str:
        C = self.C
        if tcp.flag_rst: return C.ROJO
        if tcp.flag_syn and not tcp.flag_ack: return C.VERDE
        if tcp.flag_fin: return C.AMARILLO
        if tcp.flag_syn and tcp.flag_ack: return C.CIAN
        return C.GRIS

    # ── 6.4 Estadísticas finales ─────────────────────────────────────────────

    def mostrar_estadisticas_finales(self, monitor: Monitor):
        C, S = self.C, self.S
        sep2 = S.LINEA_H2 * 56
        sep1 = S.LINEA_H  * 56
        dur  = monitor.duracion

        print(f"\n\n  {C.CIAN}{C.NEGRITA}{sep2}{C.RESET}")
        print(f"  {C.BLANCO}{C.NEGRITA}  RESUMEN DE SESION{C.RESET}")
        print(f"  {C.CIAN}{sep2}{C.RESET}\n")

        # Métricas
        for clave, valor in [
            ("Duracion",       f"{dur:.1f} s"),
            ("Paquetes total", f"{monitor.total:,}"),
            ("Bytes totales",  _humanizar_bytes(monitor.bytes_totales)),
            ("Paq / segundo",  f"{monitor.pps:.1f} pps"),
            ("Bytes / segundo",_humanizar_bytes(monitor.bps) + "/s"),
        ]:
            print(f"  {C.GRIS}{clave:<18}{C.RESET}  {C.BLANCO}{C.NEGRITA}{valor}{C.RESET}")

        # Por protocolo
        if monitor.por_protocolo:
            print(f"\n  {C.GRIS}{sep1}{C.RESET}")
            print(f"  {C.GRIS}Distribucion por protocolo:{C.RESET}\n")
            for proto, cnt in monitor.por_protocolo.most_common():
                pct   = 100 * cnt / monitor.total if monitor.total else 0
                bar   = _barra(pct, 24, S)
                color = _color_protocolo(proto, C)
                print(f"  {color}{C.NEGRITA}{proto:<8}{C.RESET}  {color}{bar}{C.RESET}  {C.BLANCO}{cnt:>6}{C.RESET}  {C.GRIS}{pct:5.1f}%{C.RESET}")

        # Top IPs origen
        top_orig = monitor.top_ips_origen(5)
        if top_orig:
            print(f"\n  {C.GRIS}{sep1}{C.RESET}")
            print(f"  {C.GRIS}Top IPs de origen:{C.RESET}\n")
            for i, (ip, cnt) in enumerate(top_orig, 1):
                print(f"  {C.AMARILLO}{i}.{C.RESET} {C.AMARILLO}{ip:<20}{C.RESET}  {cnt} paquetes")

        # Top puertos
        top_puertos = monitor.top_puertos(5)
        if top_puertos:
            print(f"\n  {C.GRIS}{sep1}{C.RESET}")
            print(f"  {C.GRIS}Top puertos destino:{C.RESET}\n")
            for i, (puerto, cnt) in enumerate(top_puertos, 1):
                servicio = _nombre_servicio(puerto)
                print(f"  {C.AZUL}{C.NEGRITA}:{puerto:<6}{C.RESET}  {C.GRIS}{servicio:<14}{C.RESET}  {cnt} conexiones")

        print(f"\n  {C.CIAN}{sep2}{C.RESET}")
        print(f"  {C.VERDE}{S.OK}  Sniffer detenido correctamente.{C.RESET}\n")

    def error(self, mensaje: str):
        C, S = self.C, self.S
        print(f"\n  {C.ROJO}{S.ERR}  {mensaje}{C.RESET}\n")

    def aviso(self, mensaje: str):
        C = self.C
        print(f"  {C.AMARILLO}[!]{C.RESET}  {mensaje}")


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 7 — Helpers internos
# ════════════════════════════════════════════════════════════════════════════

def _humanizar_bytes(n: float) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

def _barra(pct: float, ancho: int, S) -> str:
    lleno = int(pct / 100 * ancho)
    return S.LLENO * lleno + S.VACIO * (ancho - lleno)

def _es_local(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.16.")) or ip == "127.0.0.1"

def _es_externa(ip: str) -> bool:
    return not _es_local(ip)

def _nombre_servicio(puerto: int) -> str:
    return {
        20: "FTP-data",  21: "FTP",        22: "SSH",
        23: "Telnet",    25: "SMTP",        53: "DNS",
        67: "DHCP",      80: "HTTP",       110: "POP3",
       143: "IMAP",     443: "HTTPS",      993: "IMAPS",
       995: "POP3S",   3306: "MySQL",     3389: "RDP",
      5432: "PostgreSQL", 6379: "Redis",  8080: "HTTP-alt",
      8443: "HTTPS-alt", 27017: "MongoDB",
    }.get(puerto, "—")