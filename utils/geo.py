import sys
import subprocess
import os

# --- Lógica de Instalación Automática ---
def _intentar_instalar_requests():
    """Intenta instalar requests y reinicia el script."""
    print("\n[?] Configurando dependencias de geolocalización...")
    try:
        # 1. Asegurar que pip existe
        subprocess.run([sys.executable, "-m", "ensurepip", "--default-pip"], check=True, capture_output=True)
        # 2. Instalar requests
        subprocess.run([sys.executable, "-m", "pip", "install", "requests"], check=True)
        print("    [✔] Instalación exitosa. Reiniciando...")
        # 3. Reiniciar proceso
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        print(f"    [!] No se pudo instalar automáticamente: {e}")
        print("    [!] Continuando sin geolocalización.")
        return False

# --- Carga de Librería ---
_geo_listo = False
try:
    import requests
    _geo_listo = True
except ImportError:
    # Solo intentamos instalar si el usuario está en una terminal interactiva
    if sys.stdin.isatty():
        _geo_listo = _intentar_instalar_requests()

# --- Cache y Función Principal ---
_cache_geo = {}

def obtener_pais(ip: str) -> str:
    """
    Obtiene el código de país de una IP. 
    Esta función SIEMPRE está disponible para evitar ImportErrors.
    """
    if not _geo_listo:
        return "—"
    
    # Ignorar IPs locales/privadas
    if ip.startswith(("127.", "192.168.", "10.", "172.16.", "172.31.", "fe80", "::1")):
        return "LOC"

    if ip in _cache_geo:
        return _cache_geo[ip]

    try:
        # Timeout agresivo para no ralentizar el sniffer
        url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        res = requests.get(url, timeout=0.5)
        if res.status_code == 200:
            code = res.json().get("countryCode", "—")
            _cache_geo[ip] = code
            return code
    except:
        pass
    
    return "—"