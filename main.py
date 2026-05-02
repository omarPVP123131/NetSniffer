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
        metavar="IFACE",
        default=None,
        help="Interfaz de red a escuchar (ej: eth0, wlan0). Por defecto: automática.",
    )
    parser.add_argument(
        "-p", "--protocolo",
        metavar="PROTO",
        default=None,
        choices=["tcp", "udp", "icmp", "todos"],
        help="Filtrar por protocolo: tcp | udp | icmp | todos (defecto: todos).",
    )
    parser.add_argument(
        "--ip-origen",
        metavar="IP",
        default=None,
        help="Filtrar por IP de origen (ej: 192.168.1.1).",
    )
    parser.add_argument(
        "--ip-destino",
        metavar="IP",
        default=None,
        help="Filtrar por IP de destino.",
    )
    parser.add_argument(
        "--puerto",
        metavar="PUERTO",
        type=int,
        default=None,
        help="Filtrar por puerto (TCP/UDP).",
    )
    parser.add_argument(
        "-n", "--limite",
        metavar="N",
        type=int,
        default=0,
        help="Detener tras capturar N paquetes (0 = sin límite).",
    )
    parser.add_argument(
        "-o", "--salida",
        metavar="ARCHIVO",
        default=None,
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

    # ── Configuración global ────────────────────────────────────────────────
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

    # ── Interfaz de terminal ────────────────────────────────────────────────
    terminal = Terminal(config)
    terminal.mostrar_banner()
    terminal.mostrar_configuracion(config)

    # ── Motor de filtros ────────────────────────────────────────────────────
    filtros = MotorFiltros(config)

    # ── Monitor de estadísticas ─────────────────────────────────────────────
    monitor = Monitor()

    # ── Sniffer principal ───────────────────────────────────────────────────
    sniffer = Sniffer(config, filtros, monitor, terminal)

    try:
        sniffer.iniciar()
    except KeyboardInterrupt:
        pass  # Manejado internamente en sniffer.iniciar()
    finally:
        terminal.mostrar_estadisticas_finales(monitor)


if __name__ == "__main__":
    main()
