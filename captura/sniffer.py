"""
captura/sniffer.py
─────────────────────────────────────────────────────────────────────────────
Núcleo de la herramienta: crea el raw socket, recibe paquetes en bucle
y los distribuye al resto de módulos.

Flujo por paquete:
  1. recvfrom() → bytes crudos del SO
  2. parsers.protocolos.parsear_ip() → PaqueteIP estructurado
  3. filtros.MotorFiltros.aceptar() → ¿cumple los criterios?
  4. Si sí:
       a. estadisticas.Monitor.registrar()
       b. interfaz.Terminal.imprimir_paquete()
       c. salida.EscritorBase.escribir() (opcional)
  5. Si se alcanzó el límite → detener

Separar el bucle de captura de los parsers, filtros y UI permite probar
cada capa de forma independiente.
"""

import os
import socket

from config.configuracion import Configuracion
from filtros.motor import MotorFiltros
from estadisticas.monitor import Monitor
from interfaz.terminal import Terminal
from parsers.protocolos import parsear_ip
from salida.escritor import crear_escritor


class Sniffer:
    """Gestiona el ciclo de vida del raw socket y el bucle de captura."""

    def __init__(
        self,
        config: Configuracion,
        filtros: MotorFiltros,
        monitor: Monitor,
        terminal: Terminal,
    ):
        self._config   = config
        self._filtros  = filtros
        self._monitor  = monitor
        self._terminal = terminal
        self._escritor = crear_escritor(config.archivo_salida)
        self._conteo   = 0          # paquetes aceptados (post-filtro)

    # ── API pública ──────────────────────────────────────────────────────────

    def iniciar(self):
        """Abre el socket y comienza el bucle de captura."""
        sock = self._crear_socket()
        try:
            self._bucle(sock)
        except KeyboardInterrupt:
            pass
        finally:
            # Desactivar modo promiscuo en Windows
            if os.name == "nt":
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            sock.close()
            if self._escritor:
                self._escritor.cerrar()

    # ── Creación del socket ──────────────────────────────────────────────────

    def _crear_socket(self) -> socket.socket:
        """
        Crea un raw socket adaptado al SO.

        Windows  → AF_INET  + IPPROTO_IP   + modo promiscuo (SIO_RCVALL)
        Linux    → AF_PACKET + SOCK_RAW    (incluye encabezado Ethernet)
        macOS    → AF_INET  + IPPROTO_IP   (no admite AF_PACKET)
        """
        try:
            if os.name == "nt":
                # ── Windows ────────────────────────────────────────────────
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                # Vincular a la IP local para recibir tráfico entrante
                ip_local = socket.gethostbyname(socket.gethostname())
                sock.bind((ip_local, 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            else:
                # ── Linux / macOS ───────────────────────────────────────────
                # ETH_P_ALL (0x0003) captura todos los protocolos Ethernet
                ETH_P_ALL = 0x0003
                sock = socket.socket(
                    socket.AF_PACKET,
                    socket.SOCK_RAW,
                    socket.htons(ETH_P_ALL),
                )
                # Vincular a interfaz específica si se indicó
                if self._config.interfaz:
                    sock.bind((self._config.interfaz, 0))

        except PermissionError:
            raise PermissionError(
                "No tienes permiso para abrir un raw socket. "
                "Ejecuta con sudo (Linux) o como Administrador (Windows)."
            )

        return sock

    # ── Bucle principal ──────────────────────────────────────────────────────

    def _bucle(self, sock: socket.socket):
        """Recibe paquetes en bucle infinito hasta alcanzar el límite o Ctrl+C."""
        while True:
            datos_crudos, _ = sock.recvfrom(65535)

            # Linux AF_PACKET incluye 14 bytes de encabezado Ethernet
            # que debemos saltar para llegar al encabezado IP.
            if os.name != "nt":
                datos_ip = datos_crudos[14:]
            else:
                datos_ip = datos_crudos

            paquete = parsear_ip(datos_ip)
            if paquete is None:
                continue    # Paquete malformado o demasiado corto

            # ── Aplicar filtros ──────────────────────────────────────────────
            if not self._filtros.aceptar(paquete):
                continue

            # ── Registrar + mostrar + guardar ────────────────────────────────
            self._conteo += 1
            self._monitor.registrar(paquete)
            self._terminal.imprimir_paquete(paquete)

            if self._escritor:
                self._escritor.escribir(paquete, self._conteo)

            # ── Verificar límite ─────────────────────────────────────────────
            limite = self._config.limite
            if limite and self._conteo >= limite:
                print(f"\n  Límite de {limite} paquetes alcanzado. Deteniendo...")
                break
