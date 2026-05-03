"""
captura/sniffer.py
─────────────────────────────────────────────────────────────────────────────
Núcleo de la herramienta: crea el raw socket, recibe paquetes en bucle
y los distribuye al resto de módulos.

Flujo por paquete:
  1. recvfrom() con timeout de 1 s → bytes crudos del SO
  2. parsers.protocolos.desempaquetar_red() → PaqueteIP estructurado
  3. filtros.MotorFiltros.aceptar() → ¿cumple los criterios?
  4. Si sí:
       a. estadisticas.Monitor.registrar()
       b. terminal.encolar_paquete()   ← NUNCA escribe stdout directamente
       c. salida.EscritorBase.escribir() (opcional)
  5. Si terminal.pausado → espera sin capturar
  6. Si terminal.activo es False o se alcanzó el límite → detener

INTEGRACIÓN CON LA ARQUITECTURA ANTI-BLOQUEO
─────────────────────────────────────────────
  · El sniffer NUNCA llama a terminal.imprimir_paquete() directamente.
    Solo llama a terminal.encolar_paquete(), que es O(1) y nunca bloquea.
  · El hilo de UI de Terminal vacía esa cola y escribe en stdout.
    Si Windows bloquea stdout por un clic, SOLO el hilo de UI se congela;
    este bucle de captura sigue funcionando sin interrupción.
  · terminal.pausado y terminal.activo son flags thread-safe (threading.Event
    y un bool volátil) que se pueden leer desde cualquier hilo sin locks.
"""

import os
import socket
import time

from config.configuracion import Configuracion
from filtros.motor import MotorFiltros
from estadisticas.monitor import Monitor
from interfaz.terminal import Terminal
from parsers.protocolos import desempaquetar_red
from salida.escritor import crear_escritor


class Sniffer:
    """Gestiona el ciclo de vida del raw socket y el bucle de captura."""

    # Timeout del socket en segundos.
    # Valor corto → el bucle revisa terminal.activo / terminal.pausado
    # con frecuencia sin consumir CPU en busy-wait.
    _SOCKET_TIMEOUT: float = 1.0

    def __init__(
        self,
        config: Configuracion,
        filtros: MotorFiltros,
        monitor: Monitor,
        terminal: Terminal,
    ):
        self._config    = config
        self._filtros   = filtros
        self._monitor   = monitor
        self._terminal  = terminal
        self._escritor  = crear_escritor(config.archivo_salida)
        self._conteo    = 0          # paquetes aceptados (post-filtro)
        self._corriendo = False      # se pone False con detener()

    # ── API pública ──────────────────────────────────────────────────────────

    def iniciar(self) -> None:
        """
        Abre el socket y comienza el bucle de captura.
        Llamar desde un hilo dedicado (ver main.py).
        Termina cuando:
          · detener() es llamado  (Q / Escape / callback on_salida)
          · terminal.activo pasa a False
          · se alcanza el límite de paquetes
          · KeyboardInterrupt (Ctrl+C desde el shell)
        """
        self._corriendo = True
        sock = self._crear_socket()
        try:
            self._bucle(sock)
        except KeyboardInterrupt:
            pass
        finally:
            self._cerrar(sock)

    def detener(self) -> None:
        """
        Señala al bucle que debe terminar en el próximo ciclo.
        Thread-safe: se puede llamar desde cualquier hilo.
        """
        self._corriendo = False

    # ── Creación del socket ──────────────────────────────────────────────────

    def _crear_socket(self) -> socket.socket:
        try:
            if os.name == "nt":
                sock = socket.socket(
                    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP
                )
                # Detectar la IP de la interfaz activa usando una conexión UDP
                # temporal (no envía datos, solo consulta la tabla de rutas).
                s_temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s_temp.connect(("8.8.8.8", 80))
                    ip_local = s_temp.getsockname()[0]
                except Exception:
                    ip_local = socket.gethostbyname(socket.gethostname())
                finally:
                    s_temp.close()

                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((ip_local, 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            else:
                # Linux / macOS
                ETH_P_ALL = 0x0003
                sock = socket.socket(
                    socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
                )
                if self._config.interfaz:
                    sock.bind((self._config.interfaz, 0))

        except PermissionError:
            raise PermissionError(
                "Se requieren privilegios de administrador.\n"
                "Windows: ejecuta cmd.exe o PowerShell como Administrador.\n"
                "Linux/macOS: usa sudo python main.py"
            )

        sock.settimeout(self._SOCKET_TIMEOUT)
        return sock

    # ── Bucle principal ──────────────────────────────────────────────────────

    def _bucle(self, sock: socket.socket) -> None:
        """
        Bucle de captura desacoplado de la UI.

        El único punto de comunicación con Terminal es encolar_paquete(),
        que es una operación O(1) que nunca bloquea.
        """
        modo_debug = getattr(self._config, "modo_debug", False)

        while self._corriendo and self._terminal.activo:

            # ── Pausa interactiva (tecla P) ──────────────────────────────────
            # Cuando está pausado esperamos en ciclos cortos para seguir
            # revisando terminal.activo (por si el usuario pulsa Q durante
            # la pausa).
            if self._terminal.pausado:
                time.sleep(0.05)
                continue

            # ── Recibir paquete ──────────────────────────────────────────────
            try:
                datos_crudos, _ = sock.recvfrom(65535)
            except socket.timeout:
                # Sin tráfico durante _SOCKET_TIMEOUT segundos: volver al
                # inicio del bucle para revisar los flags de control.
                continue
            except OSError:
                # Socket cerrado externamente (p.ej. durante el apagado).
                break

            # ── Parsear ──────────────────────────────────────────────────────
            # En Linux/macOS los primeros 14 bytes son la cabecera Ethernet.
            datos_red = datos_crudos[14:] if os.name != "nt" else datos_crudos
            paquete = desempaquetar_red(datos_red)
            if paquete is None:
                continue

            # ── Filtrar ──────────────────────────────────────────────────────
            if not self._filtros.aceptar(paquete):
                continue

            # ── Registrar y distribuir ───────────────────────────────────────
            self._conteo += 1
            self._monitor.registrar(paquete)

            # CLAVE ANTI-BLOQUEO: encolar, nunca imprimir directamente.
            # El Hilo de UI de Terminal drena esta cola de forma asíncrona.
            self._terminal.encolar_paquete(paquete)

            if self._escritor:
                try:
                    self._escritor.escribir(paquete, self._conteo)
                except Exception as e:
                    if modo_debug:
                        self._terminal.aviso(f"Error al escribir en archivo: {e}")

            # ── Límite de paquetes ───────────────────────────────────────────
            if self._config.limite and self._conteo >= self._config.limite:
                self._corriendo = False
                break

            # ── Errores no fatales ───────────────────────────────────────────
            # (el except está fuera del bloque try de recvfrom para no
            #  silenciar errores de parseo/filtro que no son de red)

        # El bucle terminó: señalar a Terminal para que también pare
        # (cubre el caso de límite de paquetes sin que el usuario pulse Q)
        if not self._terminal.activo is False:
            self._terminal.detener()

    # ── Cierre limpio ────────────────────────────────────────────────────────

    def _cerrar(self, sock: socket.socket) -> None:
        """Desactiva el modo promiscuo (Windows) y cierra el socket."""
        if os.name == "nt":
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        try:
            sock.close()
        except Exception:
            pass
        if self._escritor:
            try:
                self._escritor.cerrar()
            except Exception:
                pass