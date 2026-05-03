#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║           NetSniffer  —  Analizador de Red           ║
║         Herramienta de captura de paquetes           ║
╚══════════════════════════════════════════════════════╝

Punto de entrada principal. Orquesta todos los módulos.
"""

import sys
import os
import argparse
import threading

# ── Verificar privilegios antes de importar módulos de red ──────────────────
from utils.permisos import verificar_privilegios
verificar_privilegios()

# ── Importar módulos del proyecto ────────────────────────────────────────────
from interfaz.terminal import Terminal
from captura.sniffer import Sniffer
from filtros.motor import MotorFiltros
from estadisticas.monitor import Monitor
from config.configuracion import Configuracion


def construir_argumentos():
    """Define y parsea los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        prog="netsniffer",
        description="Analizador de tráfico de red en tiempo real",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-i", "--interfaz",
        metavar="IFACE", default=None,
        help="Interfaz de red a escuchar (ej: eth0, wlan0). Por defecto: automática.",
    )
    parser.add_argument(
        "-p", "--protocolo",
        metavar="PROTO", default=None,
        choices=["tcp", "udp", "icmp", "todos"],
        help="Filtrar por protocolo: tcp | udp | icmp | todos (defecto: todos).",
    )
    parser.add_argument(
        "--ip-origen",
        metavar="IP", default=None,
        help="Filtrar por IP de origen (ej: 192.168.1.1).",
    )
    parser.add_argument(
        "--ip-destino",
        metavar="IP", default=None,
        help="Filtrar por IP de destino.",
    )
    parser.add_argument(
        "--puerto",
        metavar="PUERTO", type=int, default=None,
        help="Filtrar por puerto (TCP/UDP).",
    )
    parser.add_argument(
        "-n", "--limite",
        metavar="N", type=int, default=0,
        help="Detener tras capturar N paquetes (0 = sin límite).",
    )
    parser.add_argument(
        "-o", "--salida",
        metavar="ARCHIVO", default=None,
        help="Guardar paquetes capturados en un archivo .txt o .csv.",
    )
    parser.add_argument(
        "--sin-color",
        action="store_true",
        help="Desactivar colores en la salida (útil para pipes).",
    )
    parser.add_argument(
        "--modo-silencioso",
        action="store_true",
        help="Solo muestra estadísticas al final, sin imprimir cada paquete.",
    )
    return parser.parse_args()


def main():
    args = construir_argumentos()

    # ── Configuración global ─────────────────────────────────────────────────
    config = Configuracion(
        interfaz=args.interfaz,
        protocolo=args.protocolo or "todos",
        ip_origen=args.ip_origen,
        ip_destino=args.ip_destino,
        puerto=args.puerto,
        limite=args.limite,
        archivo_salida=args.salida,
        sin_color=args.sin_color,
        modo_silencioso=args.modo_silencioso,
    )

    # ── Interfaz de terminal ─────────────────────────────────────────────────
    terminal = Terminal(config)
    terminal.mostrar_banner()
    terminal.mostrar_configuracion(config)

    # ── Motor de filtros y monitor ───────────────────────────────────────────
    filtros = MotorFiltros(config)
    monitor = Monitor()

    # ── Sniffer principal ────────────────────────────────────────────────────
    sniffer = Sniffer(config, filtros, monitor, terminal)

    # ── Conectar callback de salida ──────────────────────────────────────────
    # Cuando el usuario pulse Q / Escape, terminal llama a sniffer.detener(),
    # que pone _corriendo=False y el bucle termina en el siguiente ciclo.
    terminal.on_salida = sniffer.detener

    # ── Arrancar lector de teclado (P / Q / Ctrl+C) ──────────────────────────
    terminal.iniciar_lector_teclado()

    # ── Lanzar captura en su propio hilo ─────────────────────────────────────
    #
    # Por qué hilo separado:
    #   · El hilo principal queda libre para atender señales del SO (SIGINT).
    #     Python solo despacha señales en el hilo principal; si recvfrom()
    #     bloqueara aquí, Ctrl+C tardaría hasta el próximo timeout de 1 s.
    #   · En Windows, un clic que bloquee stdout NO toca recvfrom() porque
    #     corren en hilos distintos. La captura nunca para por un clic.
    #
    hilo_captura = threading.Thread(
        target=sniffer.iniciar,
        name="captura",
        daemon=True,          # muere si el proceso principal termina
    )
    hilo_captura.start()

    # ── Loop principal: espera activa con join corto ──────────────────────────
    #
    # join(0.25) → el hilo principal "despierta" 4 veces por segundo.
    # Esto permite que Python procese SIGINT (Ctrl+C desde el shell)
    # incluso cuando la captura está bloqueada en recvfrom().
    #
    try:
        while hilo_captura.is_alive():
            hilo_captura.join(timeout=0.25)
    except KeyboardInterrupt:
        # Ctrl+C directo desde el shell (no capturado por el lector de teclado)
        terminal.detener()
        sniffer.detener()
        hilo_captura.join(timeout=2.0)

    # ── Apagar UI y mostrar resumen ───────────────────────────────────────────
    terminal.detener()
    terminal.mostrar_estadisticas_finales(monitor)


if __name__ == "__main__":
    main()