"""
interfaz/terminal.py
═══════════════════════════════════════════════════════════════════════════════
NetSniffer — Interfaz de terminal multiplataforma con Rich.

ARQUITECTURA ANTI-BLOQUEO (el problema real de Windows)
────────────────────────────────────────────────────────
En Windows, cmd.exe y PowerShell clásico entran en "modo de selección de
marcas" cuando el usuario hace clic izquierdo. Ese modo SUSPENDE toda
escritura en stdout hasta que el usuario presione Escape o Enter. Esto
congela cualquier print() o Console.print() de Rich, y con él todo el
programa.

La solución no es evitar el bloqueo de stdout (imposible sin deshabilitar
el modo selección del sistema), sino DESACOPLAR completamente los tres planos:

  ┌──────────────────────────────────────────────────────────┐
  │  HILO DE CAPTURA   →   deque   →   HILO DE UI            │
  │  (nunca escribe)       (lock)      (solo escribe stdout)  │
  │                                                           │
  │  HILO DE TECLADO   →   eventos  →  flags de estado        │
  │  (msvcrt / termios)               (pausado / activo)      │
  └──────────────────────────────────────────────────────────┘

  1. HILO DE CAPTURA  — encola paquetes en una deque, NUNCA escribe stdout.
  2. HILO DE UI       — vacía la deque y llama a Console.print() cada ~80 ms.
                        Si stdout se bloquea por un clic, SOLO este hilo
                        se congela; el hilo de captura sigue sin problema.
  3. HILO DE TECLADO  — no bloqueante:
       · Windows: msvcrt.kbhit() + msvcrt.getwch()  (sin Enter)
       · Unix/Mac: select() + termios raw mode       (sin Enter)
     Detecta P (pausa), Q/Escape (salida), Ctrl+C (salida).

INTEGRACIÓN EN MAIN.PY
────────────────────────
    terminal = Terminal(config)
    terminal.mostrar_banner()
    terminal.mostrar_configuracion(config)
    terminal.iniciar_lector_teclado()      # arranca hilos internos

    # En el hilo de captura:
    while terminal.activo:
        if terminal.pausado:
            time.sleep(0.05)
            continue
        paquete = capturar_siguiente()
        terminal.encolar_paquete(paquete)

    terminal.detener()
    terminal.mostrar_estadisticas_finales(monitor)

DEPENDENCIAS
────────────
    pip install rich
    (msvcrt y termios son stdlib — sin instalación extra)
"""

from __future__ import annotations

import os
import sys
import time
import threading
import signal
from collections import deque
from typing import Optional, Callable

# ── Rich ─────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.rule import Rule
    from rich.style import Style
    from rich.align import Align
    from rich import box
    RICH_OK = True
except ImportError:
    RICH_OK = False

from config.configuracion import Configuracion
from parsers.protocolos import PaqueteIP, PaqueteTCP, PaqueteUDP, PaqueteICMP
from estadisticas.monitor import Monitor


# ═══════════════════════════════════════════════════════════════════════════
# §1  LECTOR DE TECLADO NO BLOQUEANTE (multiplataforma)
# ═══════════════════════════════════════════════════════════════════════════

class _LectorTeclado:
    """
    Lee teclas sin bloquear el hilo principal, sin necesitar Enter.

    • Windows  — msvcrt.kbhit() + msvcrt.getwch()
                 Funciona en cmd.exe, PowerShell, Windows Terminal.
                 No requiere privilegios adicionales.

    • Unix/Mac — select() sobre stdin + termios en modo raw.
                 Restaura la configuración original de la terminal al salir.
                 Si stdin no es una tty (redirección), simplemente no hace nada.

    El hilo es daemon=True: muere automáticamente con el proceso principal.
    """

    def __init__(self, callback: Callable[[str], None]):
        self._cb    = callback
        self._vivo  = True
        self._hilo  = threading.Thread(
            target=self._bucle,
            name="kbd-reader",
            daemon=True,
        )

    def iniciar(self) -> None:
        self._hilo.start()

    def detener(self) -> None:
        self._vivo = False

    # ── bucle interno ────────────────────────────────────────────────────────

    def _bucle(self) -> None:
        if os.name == "nt":
            self._bucle_windows()
        else:
            self._bucle_unix()

    def _bucle_windows(self) -> None:
        try:
            import msvcrt
        except ImportError:
            return                          # entorno muy raro sin msvcrt

        while self._vivo:
            try:
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()    # un carácter, sin Enter
                    self._cb(ch)
                else:
                    time.sleep(0.05)
            except Exception:
                time.sleep(0.1)

    def _bucle_unix(self) -> None:
        try:
            import select
            import termios
            import tty
        except ImportError:
            return                          # FreeBSD sin termios, etc.

        fd = sys.stdin.fileno()
        try:
            modo_orig = termios.tcgetattr(fd)
        except termios.error:
            return                          # stdin redirigido, no interactivo

        try:
            tty.setraw(fd)                  # cada tecla llega sin Enter
            while self._vivo:
                r, _, _ = select.select([sys.stdin], [], [], 0.05)
                if r:
                    ch = sys.stdin.read(1)
                    self._cb(ch)
        except Exception:
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, modo_orig)
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════
# §2  HILO DE UI — escritura asíncrona en stdout
# ═══════════════════════════════════════════════════════════════════════════

class _HiloUI:
    """
    Vacía la cola de paquetes y los imprime en pantalla cada INTERVALO seg.

    Al separar escritura de captura:
      • Un clic en Windows bloquea SOLO este hilo (stdout).
      • El hilo de captura sigue encolando sin interrupción.
      • Al liberar el clic, este hilo se reanuda e imprime todo lo acumulado.
    """

    INTERVALO: float = 0.08   # ~12 fps

    def __init__(self, cola: deque, cb_imprimir: Callable) -> None:
        self._cola  = cola
        self._cb    = cb_imprimir
        self._vivo  = True
        self._hilo  = threading.Thread(
            target=self._bucle,
            name="ui-writer",
            daemon=True,
        )

    def iniciar(self) -> None:
        self._hilo.start()

    def detener(self) -> None:
        self._vivo = False
        self._hilo.join(timeout=1.5)

    def _bucle(self) -> None:
        while self._vivo:
            self._vaciar()
            time.sleep(self.INTERVALO)
        self._vaciar()      # vaciado final antes de terminar

    def _vaciar(self) -> None:
        while self._cola:
            try:
                self._cb(self._cola.popleft())
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════
# §3  PALETA DE ESTILOS
# ═══════════════════════════════════════════════════════════════════════════

class E:
    """Estilos semánticos centralizados (nombre corto para uso interno)."""
    # IPs
    IP_LOCAL    = Style(color="yellow")
    IP_EXTERNA  = Style(color="red",            bold=True)
    IP_DEST_OK  = Style(color="green")
    IP_CIAN     = Style(color="cyan")
    # Fila
    HORA        = Style(color="white",          dim=True)
    ID_PKT      = Style(color="bright_black")
    # Protocolos
    TCP         = Style(color="bright_blue",    bold=True)
    UDP         = Style(color="bright_green",   bold=True)
    ICMP        = Style(color="bright_yellow",  bold=True)
    PROTO_DEF   = Style(color="bright_magenta", bold=True)
    # Flags TCP
    FLAG_RST    = Style(color="red",            bold=True)
    FLAG_SYN    = Style(color="green",          bold=True)
    FLAG_FIN    = Style(color="yellow",         bold=True)
    FLAG_SYNACK = Style(color="cyan")
    FLAG_DEF    = Style(color="bright_black")
    # Estado
    OK          = Style(color="green",          bold=True)
    ERROR       = Style(color="red",            bold=True)
    AVISO       = Style(color="yellow")


# ═══════════════════════════════════════════════════════════════════════════
# §4  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _humanizar_bytes(n: float) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

def _es_local(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.16.")) or ip == "127.0.0.1"

def _nombre_servicio(puerto: int) -> str:
    return {
        20: "FTP-data",  21: "FTP",       22: "SSH",      23: "Telnet",
        25: "SMTP",      53: "DNS",       67: "DHCP",     80: "HTTP",
       110: "POP3",     143: "IMAP",     443: "HTTPS",   993: "IMAPS",
       995: "POP3S",   3306: "MySQL",   3389: "RDP",    5432: "PostgreSQL",
      6379: "Redis",   8080: "HTTP-alt", 8443: "HTTPS-alt", 27017: "MongoDB",
    }.get(puerto, "—")

def _estilo_proto(nombre: str) -> Style:
    return {"TCP": E.TCP, "UDP": E.UDP, "ICMP": E.ICMP}.get(nombre, E.PROTO_DEF)

def _estilo_flags(tcp: PaqueteTCP) -> Style:
    if tcp.flag_rst:                      return E.FLAG_RST
    if tcp.flag_syn and not tcp.flag_ack: return E.FLAG_SYN
    if tcp.flag_fin:                      return E.FLAG_FIN
    if tcp.flag_syn and tcp.flag_ack:     return E.FLAG_SYNACK
    return E.FLAG_DEF

def _barra(pct: float, ancho: int, color: str) -> Text:
    lleno = max(0, min(ancho, int(pct / 100 * ancho)))
    t = Text()
    t.append("█" * lleno,           style=color)
    t.append("░" * (ancho - lleno), style="bright_black dim")
    return t

def _so_nombre() -> str:
    if os.name == "nt":          return "Windows"
    if sys.platform == "darwin": return "macOS"
    return "Linux"


# ═══════════════════════════════════════════════════════════════════════════
# §5  CLASE PRINCIPAL Terminal
# ═══════════════════════════════════════════════════════════════════════════

class Terminal:
    """
    Gestiona toda la presentación visual de NetSniffer.

    Propiedades de estado (thread-safe, para leer desde el hilo de captura)
    ────────────────────────────────────────────────────────────────────────
        terminal.activo   → bool  (False cuando el usuario pulsa Q o Ctrl+C)
        terminal.pausado  → bool  (True mientras esté en pausa con P)

    Métodos principales
    ───────────────────
        mostrar_banner()
        mostrar_configuracion(config)
        iniciar_lector_teclado()        ← arranca hilos internos
        encolar_paquete(paquete)        ← llamar desde hilo de captura
        detener()                       ← llamar al acabar
        mostrar_estadisticas_finales(monitor)
        error(msg) / aviso(msg)
    """

    def __init__(self, config: Configuracion) -> None:
        if not RICH_OK:
            raise ImportError(
                "Rich no está instalado. Ejecuta:  pip install rich"
            )

        self._config   = config
        self._console  = Console(
            highlight=False,
            markup=False,
            soft_wrap=True,
            no_color=getattr(config, "sin_color", False),
        )
        self._contador = 0
        self._lock     = threading.Lock()       # protege Console.print()
        self._cola: deque = deque(maxlen=20_000)

        # ── Estado compartido (leído desde el hilo de captura) ───────────────
        self._ev_pausa  = threading.Event()     # set = en pausa
        self._activo    = True

        # ── Callback opcional al salir ───────────────────────────────────────
        self.on_salida: Optional[Callable] = None

        # ── Submódulos (se crean en iniciar_lector_teclado) ──────────────────
        self._hilo_ui: Optional[_HiloUI]        = None
        self._teclado: Optional[_LectorTeclado]  = None

    # ── Propiedades de estado (thread-safe) ──────────────────────────────────

    @property
    def activo(self) -> bool:
        return self._activo

    @property
    def pausado(self) -> bool:
        return self._ev_pausa.is_set()

    # ── API pública ──────────────────────────────────────────────────────────

    def encolar_paquete(self, paquete) -> None:
        """Thread-safe. Llamar desde el hilo de captura."""
        self._cola.append(paquete)

    def iniciar_lector_teclado(self) -> None:
        """
        Arranca el hilo de UI y el hilo de teclado.
        Llamar una sola vez, justo antes de iniciar la captura.
        """
        self._hilo_ui = _HiloUI(self._cola, self._imprimir_paquete_sync)
        self._hilo_ui.iniciar()

        self._teclado = _LectorTeclado(self._manejar_tecla)
        self._teclado.iniciar()

        # Capturamos SIGINT para salida limpia (Ctrl+C desde shell)
        try:
            signal.signal(signal.SIGINT, self._manejar_sigint)
        except (OSError, ValueError):
            pass    # algunos contextos no permiten cambiar SIGINT

    def detener(self) -> None:
        """Detiene los hilos internos de forma ordenada."""
        self._activo = False
        if self._teclado:
            self._teclado.detener()
        if self._hilo_ui:
            self._hilo_ui.detener()

    # ── Manejo de teclado ────────────────────────────────────────────────────

    def _manejar_tecla(self, ch: str) -> None:
        c = ch.lower() if isinstance(ch, str) else ""
        if c == "p":
            self._toggle_pausa()
        elif c in ("q", "\x1b"):        # Q o Escape
            self._solicitar_salida()
        elif ch in ("\x03", "\x04"):    # Ctrl+C o Ctrl+D
            self._solicitar_salida()

    def _manejar_sigint(self, *_) -> None:
        self._solicitar_salida()

    def _toggle_pausa(self) -> None:
        if self._ev_pausa.is_set():
            self._ev_pausa.clear()
            self._msg_estado("▶  Captura reanudada", "green bold", "green")
        else:
            self._ev_pausa.set()
            self._msg_estado(
                "⏸  Captura en pausa  —  [P] para reanudar  [Q] para salir",
                "yellow bold", "yellow",
            )

    def _solicitar_salida(self) -> None:
        self._activo = False
        if self.on_salida:
            try:
                self.on_salida()
            except Exception:
                pass

    # ── Banner ───────────────────────────────────────────────────────────────

    def mostrar_banner(self) -> None:
        c = self._console

        titulo = Text(justify="center")
        titulo.append("◈  ", style="cyan dim")
        titulo.append("NetSniffer ", style="bold cyan")
        titulo.append(f"v{self._config.version}", style="bold white")
        titulo.append("  ◈", style="cyan dim")

        sub = Text(
            "Captura  ·  Filtra  ·  Analiza  ·  IPv4",
            style="white dim", justify="center",
        )
        teclas = Text(
            "[P] Pausar / Reanudar    [Q] Salir    [Ctrl+C] Salir",
            style="bright_black", justify="center",
        )

        c.print()
        c.print(Panel(
            Align.center(Text.assemble(titulo, "\n", sub, "\n\n", teclas)),
            border_style="cyan",
            padding=(1, 6),
            box=box.DOUBLE,
        ))
        c.print()

        enc = (getattr(c, "encoding", None) or "utf-8").upper()
        env = Text()
        env.append("  SO: ",      style="bright_black")
        env.append(_so_nombre(),  style="yellow bold")
        env.append("   Charset: ", style="bright_black")
        env.append(enc,            style="green")
        env.append("   Color: ",   style="bright_black")
        env.append(
            "Activo" if c.is_terminal else "Sin color",
            style="green" if c.is_terminal else "bright_black",
        )
        c.print(env)
        c.print()

    # ── Configuración activa ──────────────────────────────────────────────────

    def mostrar_configuracion(self, config: Configuracion) -> None:
        c = self._console

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("k", style="cyan dim",          width=14, no_wrap=True)
        t.add_column("v", style="bright_white bold",  no_wrap=False)
        for clave, valor in [
            ("Protocolo",  config.protocolo.upper()),
            ("IP origen",  config.ip_origen  or "cualquiera"),
            ("IP destino", config.ip_destino or "cualquiera"),
            ("Puerto",     str(config.puerto) if config.puerto else "cualquiera"),
            ("Límite",     f"{config.limite} paquetes" if config.limite else "sin límite"),
            ("Salida",     config.archivo_salida or "solo pantalla"),
        ]:
            t.add_row(f"  · {clave}", valor)

        c.print(Panel(t,
                      title="[bold cyan]Sesión activa[/]",
                      border_style="cyan dim",
                      box=box.ROUNDED,
                      padding=(0, 1)))
        c.print()
        c.print(Text.assemble(
            ("  ▶  Captura iniciada", "green bold"),
            ("   ·   ", "bright_black"),
            ("[P]", "bold yellow"), (" Pausar", "bright_black"),
            ("   ·   ", "bright_black"),
            ("[Q]", "bold red"),    (" Salir", "bright_black"),
        ))
        c.print()
        self._imprimir_cabecera()

    # ── Cabecera de tabla ─────────────────────────────────────────────────────

    def _imprimir_cabecera(self) -> None:
        t = self._nueva_tabla(show_header=True)
        with self._lock:
            self._console.print(t)
            self._console.print(Rule(style="bright_black dim"))

    @staticmethod
    def _nueva_tabla(show_header: bool = False) -> Table:
        t = Table(
            box=None,
            show_header=show_header,
            show_edge=False,
            padding=(0, 1),
            header_style="bold white on grey11",
        )
        t.add_column("ID",             width=5,  style="bright_black",  no_wrap=True)
        t.add_column("HORA",           width=10, style="white dim",      no_wrap=True)
        t.add_column("ORIGEN  [PAÍS]", width=26,                         no_wrap=True)
        t.add_column("→",              width=3,  style="bright_black",  no_wrap=True, justify="center")
        t.add_column("DESTINO [PAÍS]", width=26,                         no_wrap=True)
        t.add_column("PROTO",          width=9,  style="bold",           no_wrap=True, justify="center")
        t.add_column("DETALLES",       style="bright_black",             no_wrap=True)
        return t

    # ── Imprimir paquete (llamado desde _HiloUI) ──────────────────────────────

    def _imprimir_paquete_sync(self, paquete) -> None:
        """Solo llamar desde el hilo de UI."""
        if getattr(self._config, "modo_silencioso", False):
            return

        self._contador += 1

        try:
            from utils.geo import obtener_pais
            p_orig = obtener_pais(paquete.ip_origen)
            p_dest = obtener_pais(paquete.ip_destino)
        except Exception:
            p_orig = p_dest = "??"

        ahora    = time.strftime("%H:%M:%S")
        orig_str = f"{paquete.ip_origen[:18]:<18} [{p_orig:^3}]"
        dest_str = f"{paquete.ip_destino[:18]:<18} [{p_dest:^3}]"

        e_orig = E.IP_LOCAL  if _es_local(paquete.ip_origen)    else E.IP_CIAN
        e_dest = E.IP_DEST_OK if not _es_local(paquete.ip_destino) else E.IP_LOCAL

        bg_map = {"TCP": "on blue", "UDP": "on green", "ICMP": "on dark_red"}
        bg     = bg_map.get(paquete.protocolo_nombre, "on grey23")
        proto  = Text(f" {paquete.protocolo_nombre:^7} ", style=f"bold white {bg}")

        t = self._nueva_tabla()
        t.add_row(
            Text(f"{self._contador:04d}", style=E.ID_PKT),
            Text(ahora,                  style=E.HORA),
            Text(orig_str,               style=e_orig),
            Text("→",                    style="bright_black"),
            Text(dest_str,               style=e_dest),
            proto,
            self._texto_transporte(paquete),
        )

        with self._lock:
            self._console.print(t)

    # ── Capa de transporte ────────────────────────────────────────────────────

    @staticmethod
    def _texto_transporte(paquete: PaqueteIP) -> Text:
        tl = paquete.transporte

        if isinstance(tl, PaqueteTCP):
            txt = Text()
            txt.append(f":{tl.puerto_origen} → :{tl.puerto_destino}", style="bright_black")
            txt.append(f"  [{tl.flags_str}]", style=_estilo_flags(tl))
            txt.append(f"  win={tl.tamano_ventana}", style="bright_black dim")
            return txt

        if isinstance(tl, PaqueteUDP):
            txt = Text()
            txt.append(f":{tl.puerto_origen} → :{tl.puerto_destino}", style="bright_black")
            txt.append(f"  len={tl.longitud}", style="bright_black dim")
            return txt

        if isinstance(tl, PaqueteICMP):
            return Text(
                f"{tl.descripcion}  (t={tl.tipo} c={tl.codigo})",
                style="bright_black",
            )

        return Text(
            f"TTL={paquete.ttl}  tam={paquete.tamano_total}B",
            style="bright_black dim",
        )

    # ── Mensaje de estado en panel (pausa / reanudar) ─────────────────────────

    def _msg_estado(self, texto: str, estilo_texto: str, estilo_borde: str) -> None:
        with self._lock:
            self._console.print()
            self._console.print(Panel(
                Text(f"  {texto}  ", style=estilo_texto, justify="center"),
                border_style=estilo_borde,
                box=box.ROUNDED,
                padding=(0, 2),
            ))
            self._console.print()

    # ── Estadísticas finales ──────────────────────────────────────────────────

    def mostrar_estadisticas_finales(self, monitor: Monitor) -> None:
        c   = self._console
        dur = monitor.duracion

        c.print()
        c.print(Rule("[bold cyan]RESUMEN DE SESIÓN[/]", style="cyan"))
        c.print()

        # ── Métricas ─────────────────────────────────────────────────────────
        tm = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
        tm.add_column("k", style="cyan dim",         width=22, no_wrap=True)
        tm.add_column("v", style="bold bright_white", no_wrap=True)
        for clave, valor in [
            ("Duración",         f"{dur:.1f} s"),
            ("Paquetes total",   f"{monitor.total:,}"),
            ("Bytes totales",    _humanizar_bytes(monitor.bytes_totales)),
            ("Paq / segundo",    f"{monitor.pps:.1f} pps"),
            ("Bytes / segundo",  _humanizar_bytes(monitor.bps) + "/s"),
        ]:
            tm.add_row(f"  {clave}", valor)
        c.print(tm)

        # ── Distribución por protocolo ────────────────────────────────────────
        if monitor.por_protocolo:
            c.print(Rule("[dim]Distribución por protocolo[/]", style="bright_black"))
            c.print()
            tp = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
            tp.add_column("p",   width=10, no_wrap=True)
            tp.add_column("b",   width=26, no_wrap=True)
            tp.add_column("n",   width=8,  justify="right")
            tp.add_column("pct", width=8,  justify="right")
            total = monitor.total or 1
            for proto, cnt in monitor.por_protocolo.most_common():
                pct   = 100 * cnt / total
                color = str(_estilo_proto(proto).color)
                tp.add_row(
                    Text(f"  {proto:<7}", style=_estilo_proto(proto)),
                    _barra(pct, 22, color),
                    Text(str(cnt), style="white"),
                    Text(f"{pct:5.1f}%", style="bright_black"),
                )
            c.print(tp)

        # ── Top IPs origen ────────────────────────────────────────────────────
        top_orig = monitor.top_ips_origen(5)
        if top_orig:
            c.print()
            c.print(Rule("[dim]Top IPs de origen[/]", style="bright_black"))
            c.print()
            to = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            to.add_column("#",    width=3,  style="bright_black")
            to.add_column("IP",   width=22, style="yellow bold")
            to.add_column("Pkts", width=12, style="white")
            for i, (ip, cnt) in enumerate(top_orig, 1):
                to.add_row(f"{i}.", ip, f"{cnt} paquetes")
            c.print(to)

        # ── Top puertos ───────────────────────────────────────────────────────
        top_puertos = monitor.top_puertos(5)
        if top_puertos:
            c.print()
            c.print(Rule("[dim]Top puertos destino[/]", style="bright_black"))
            c.print()
            tpu = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            tpu.add_column("#",        width=3,  style="bright_black")
            tpu.add_column("Puerto",   width=8,  style="blue bold")
            tpu.add_column("Servicio", width=16, style="bright_black")
            tpu.add_column("Conex.",   width=10, style="white")
            for i, (puerto, cnt) in enumerate(top_puertos, 1):
                tpu.add_row(f"{i}.", f":{puerto}", _nombre_servicio(puerto), str(cnt))
            c.print(tpu)

        # ── Top Talkers ───────────────────────────────────────────────────────
        top_talkers = monitor.top_talkers(5)
        if top_talkers and monitor.bytes_totales > 0:
            c.print()
            c.print(Rule("[dim]Top Talkers — carga de red[/]", style="bright_black"))
            c.print()
            tt = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
            tt.add_column("#",     width=3,  style="bright_black")
            tt.add_column("IP",    width=22, style="magenta bold")
            tt.add_column("Barra", width=20, no_wrap=True)
            tt.add_column("Bytes", width=12, style="white", justify="right")
            for i, (ip, b) in enumerate(top_talkers, 1):
                pct = (b / monitor.bytes_totales) * 100
                tt.add_row(f"{i}.", ip, _barra(pct, 16, "magenta"), _humanizar_bytes(b))
            c.print(tt)

        # ── Cierre ────────────────────────────────────────────────────────────
        c.print()
        c.print(Rule(style="cyan"))
        c.print(Text.assemble(
            ("  ✔  ", "green bold"),
            ("Sniffer detenido correctamente.", "white"),
        ))
        c.print()

    # ── Mensajes de estado ────────────────────────────────────────────────────

    def error(self, mensaje: str) -> None:
        with self._lock:
            self._console.print(Text.assemble(
                ("\n  ✖  ", "red bold"), (mensaje, "red"), ("\n", ""),
            ))

    def aviso(self, mensaje: str) -> None:
        with self._lock:
            self._console.print(Text.assemble(
                ("  ⚠  ", "yellow"), (mensaje, "yellow dim"),
            ))