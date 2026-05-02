"""
utils/permisos.py
─────────────────────────────────────────────────────────────────────────────
Verifica que el proceso tenga los privilegios necesarios para abrir sockets
crudos (raw sockets). En Linux/macOS se requiere ejecutar como root (UID 0).
En Windows se necesita ejecutar como Administrador.

Se llama ANTES de importar cualquier módulo de red para dar un mensaje de
error claro en lugar de una excepción críptica.
"""

import os
import sys


def verificar_privilegios():
    """Termina el programa con un mensaje claro si no hay privilegios."""
    if os.name == "nt":
        # Windows: intentamos detectar si es Administrador via ctypes
        try:
            import ctypes
            es_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            es_admin = False

        if not es_admin:
            _salir_sin_permisos("Ejecuta el script como Administrador (clic derecho → Ejecutar como administrador).")

    else:
        # Linux / macOS: UID 0 = root
        if os.geteuid() != 0:
            _salir_sin_permisos("Ejecuta el script con sudo:\n  sudo python3 main.py")


def _salir_sin_permisos(instruccion: str):
    """Imprime el error y termina."""
    print()
    print("  ┌─────────────────────────────────────────────────────────┐")
    print("  │  ✖  PERMISOS INSUFICIENTES                              │")
    print("  ├─────────────────────────────────────────────────────────┤")
    print(f"  │  Los raw sockets requieren privilegios de administrador. │")
    print(f"  │  {instruccion:<55} │")
    print("  └─────────────────────────────────────────────────────────┘")
    print()
    sys.exit(1)
