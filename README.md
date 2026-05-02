# NetSniffer 🔬

**Analizador de tráfico de red en tiempo real — hecho en Python puro**

Creado por **Omar Palomares Velasco** y dedicado a la comunidad.
Este proyecto es de código abierto, libre y gratuito para siempre.
Úsalo para aprender, diagnosticar y crecer — nunca para hacer daño.

> *"La tecnología compartida es tecnología que multiplica."*

---

## Índice

1. [¿Qué es NetSniffer?](#qué-es-netsniffer)
2. [¿Qué es un sniffer y para qué sirve?](#qué-es-un-sniffer-y-para-qué-sirve)
3. [¿Qué son los protocolos de red?](#qué-son-los-protocolos-de-red-tcp-udp-icmp)
4. [Instalación](#instalación)
5. [Primeros pasos](#primeros-pasos)
6. [Todos los argumentos](#todos-los-argumentos)
7. [Casos de uso reales](#casos-de-uso-reales)
8. [Estructura del proyecto](#estructura-del-proyecto)
9. [Guía de contribución y extensión](#guía-de-contribución-y-extensión)
10. [Solución de problemas](#solución-de-problemas)
11. [Licencia y uso ético](#licencia-y-uso-ético)
12. [Reconocimientos](#reconocimientos)

---

## ¿Qué es NetSniffer?

NetSniffer es una herramienta de línea de comandos que **captura y analiza los paquetes de datos** que viajan por tu red en tiempo real. Piénsalo como un "microscopio digital" para tu conexión de internet.

Con NetSniffer puedes:

- Ver qué programas están enviando datos y a dónde
- Aprender cómo funcionan los protocolos de red desde adentro
- Diagnosticar problemas de conectividad en casa o trabajo
- Detectar tráfico sospechoso o inesperado en tu red
- Probar aplicaciones que desarrollas y ver su tráfico real

No necesitas saber nada de redes para empezar — este README te explica todo desde cero.

---

## ¿Qué es un sniffer y para qué sirve?

Cuando tu computadora se comunica con internet (o con otras máquinas en tu red), lo hace enviando pequeños bloques de datos llamados **paquetes**. Cada vez que abres una página web, mandas un correo o haces una videollamada, tu computadora envía y recibe miles de estos paquetes por segundo.

Un **sniffer** (del inglés *to sniff*, olfatear) es un programa que intercepta esos paquetes antes de que desaparezcan y los muestra en pantalla para que puedas analizarlos. Es la misma tecnología que usan herramientas profesionales como Wireshark, pero en una versión más simple y educativa.

### ¿Para qué lo usan los profesionales?

**Aprendizaje:** Los estudiantes de redes usan sniffers para ver con sus propios ojos cómo funciona TCP, qué contiene un paquete DNS, o por qué una conexión HTTPS es segura y una HTTP no.

**Diagnóstico:** Un administrador de red puede detectar qué dispositivo está consumiendo todo el ancho de banda, o por qué una aplicación no se conecta correctamente.

**Desarrollo de software:** Un programador que crea una app de red puede verificar que su aplicación esté enviando los datos correctos al servidor correcto.

**Seguridad:** Los auditores de seguridad revisan el tráfico de una red para detectar comportamientos anómalos, conexiones no autorizadas o datos enviados sin cifrar.

---

## ¿Qué son los protocolos de red? (TCP, UDP, ICMP)

Un **protocolo** es simplemente un conjunto de reglas que dos computadoras acuerdan seguir para poder comunicarse. Es como el idioma que hablan los dispositivos entre sí.

### TCP — Transmission Control Protocol

TCP es el protocolo más usado en internet. Su característica principal es que **garantiza la entrega** de los datos.

Imagínalo como enviar un paquete por correo certificado: el destinatario firma de recibido, y si algo se pierde, se reenvía automáticamente. Por eso es más lento pero confiable.

**Lo usan:** páginas web (HTTP/HTTPS), correo electrónico, transferencia de archivos, bases de datos.

Los paquetes TCP tienen **flags** (banderas) que indican el estado de la conexión:

| Flag | Significado | Cuándo aparece |
|------|-------------|----------------|
| `SYN` | Synchronize — inicio de conexión | Al conectarse a un servidor |
| `ACK` | Acknowledge — confirmación de recibo | En casi todos los paquetes |
| `FIN` | Finish — cierre ordenado | Al terminar una conexión |
| `RST` | Reset — cierre forzado | Cuando algo sale mal |
| `PSH` | Push — enviar datos de inmediato | Al enviar datos de aplicación |

Una conexión TCP normal se ve así en NetSniffer:
```
Cliente → Servidor   TCP   SYN          (quiero conectarme)
Servidor → Cliente   TCP   SYN ACK      (acepto, confirmado)
Cliente → Servidor   TCP   ACK          (entendido, conectados)
...datos...
Cliente → Servidor   TCP   FIN ACK      (quiero cerrar)
Servidor → Cliente   TCP   FIN ACK      (de acuerdo)
```

### UDP — User Datagram Protocol

UDP es el protocolo "sin garantías". Envía los datos y no espera confirmación de que llegaron. Es como echar una carta al buzón sin certificar: más rápido, pero si se pierde, nadie te avisa.

**Lo usan:** DNS (consultas de nombres de dominio), videollamadas, juegos en línea, streaming de video. En todos estos casos, la velocidad importa más que la perfección.

### ICMP — Internet Control Message Protocol

ICMP es el protocolo de "mensajes de control" de la red. No transporta datos de usuario — transporta información sobre el estado de la red.

El comando `ping` que todos conocen usa ICMP: envía un mensaje "Echo Request" y espera un "Echo Reply". Si no llega respuesta, el host está caído o bloqueado.

| Tipo ICMP | Descripción |
|-----------|-------------|
| Echo Request (ping) | "¿Estás ahí?" |
| Echo Reply | "Sí, aquí estoy" |
| TTL expirado | El paquete viajó demasiado lejos y fue descartado |
| Destino inalcanzable | No se puede llegar a esa dirección |

### ¿Qué es el TTL?

TTL (Time To Live) es un número que cada paquete lleva consigo. Cada vez que el paquete pasa por un router, ese número baja en 1. Cuando llega a 0, el paquete se descarta. Esto evita que paquetes perdidos circulen por internet para siempre.

Un TTL de 128 generalmente indica Windows, uno de 64 suele ser Linux/macOS.

---

## Instalación

### Requisitos previos

- **Python 3.10 o superior** — [descargar aquí](https://www.python.org/downloads/)
- **Sistema operativo:** Windows 10+, Linux, macOS
- **Privilegios de administrador** (necesarios para abrir sockets de red crudos)

Para verificar tu versión de Python:
```bash
python --version
# o en Linux/macOS:
python3 --version
```

### Descargar NetSniffer

```bash
# Opción 1: Clonar con git
git clone https://github.com/omarPVP123131/NetSniffer
cd netsniffer

# Opción 2: Descargar el ZIP desde GitHub y descomprimirlo
```

### Dependencias opcionales

NetSniffer **no requiere dependencias externas** para funcionar. Sin embargo, en Windows antiguo (antes de Windows 10) puedes instalar colorama para mejor soporte de colores:

```bash
pip install colorama
```

---

## Primeros pasos

### En Linux / macOS

```bash
# Captura básica — ve TODO el tráfico
sudo python3 main.py

# Detén la captura con Ctrl+C
```

### En Windows

Abre **PowerShell o CMD como Administrador** (clic derecho → Ejecutar como administrador):

```
python main.py
```

### Lo que verás en pantalla

```
  ╔══════════════════════════════════════════════════════╗
  ║              NetSniffer v1.0.0                       ║
  ║       Captura  |  Filtra  |  Analiza  |  IPv4        ║
  ╚══════════════════════════════════════════════════════╝

  SO: Linux   Modo: Color   Charset: Unicode

  Configuracion de sesion:
  ────────────────────────────────────────────────────────
  • Protocolo     TODOS
  • IP origen     cualquiera
  ...

  N     HORA       ORIGEN               DESTINO            PROTO  INFO
  ──────────────────────────────────────────────────────────────────────
  1    14:32:01  192.168.1.10       → 8.8.8.8           TCP    :54321 → :443  [SYN]  win=65535
  2    14:32:01  8.8.8.8            → 192.168.1.10      TCP    :443 → :54321  [SYN ACK]
  3    14:32:02  192.168.1.10       → 1.1.1.1           UDP    :51234 → :53  len=45
```

**Columnas explicadas:**

| Columna | Qué significa |
|---------|---------------|
| `N` | Número de paquete en esta sesión |
| `HORA` | Hora exacta de captura |
| `ORIGEN` | IP que envió el paquete (amarillo = tu red local) |
| `DESTINO` | IP que recibió el paquete (rojo = internet) |
| `PROTO` | Protocolo usado (TCP, UDP, ICMP) |
| `INFO` | Puertos, flags TCP, o descripción ICMP |

---

## Todos los argumentos

```bash
sudo python3 main.py [opciones]
```

| Argumento | Corto | Descripción | Ejemplo |
|-----------|-------|-------------|---------|
| `--interfaz` | `-i` | Interfaz de red específica | `-i eth0` |
| `--protocolo` | `-p` | Filtrar por protocolo | `-p tcp` |
| `--ip-origen` | | Solo paquetes de esta IP | `--ip-origen 192.168.1.5` |
| `--ip-destino` | | Solo paquetes hacia esta IP | `--ip-destino 8.8.8.8` |
| `--puerto` | | Filtrar por puerto | `--puerto 443` |
| `--limite` | `-n` | Parar tras N paquetes | `-n 100` |
| `--salida` | `-o` | Guardar en archivo | `-o captura.csv` |
| `--sin-color` | | Sin colores ANSI | `--sin-color` |
| `--modo-silencioso` | | Solo estadísticas al final | `--modo-silencioso` |

---

## Casos de uso reales

### Caso 1: "¿Qué está haciendo mi computadora en internet ahora mismo?"

```bash
sudo python3 main.py
```

Deja la captura correr 30 segundos mientras no haces nada. Verás conexiones a servidores de actualizaciones, telemetría, DNS, etc. Todo lo que tu sistema hace "en segundo plano".

### Caso 2: "Quiero aprender cómo funciona DNS"

DNS es el sistema que convierte `google.com` en `142.250.x.x`. Cada vez que abres una página, tu computadora hace una consulta DNS por UDP al puerto 53.

```bash
sudo python3 main.py --protocolo udp --puerto 53
```

Ahora abre una página web en tu navegador. Verás los paquetes DNS aparecer en tiempo real: primero la consulta de tu computadora, luego la respuesta del servidor.

### Caso 3: "Quiero ver cómo se establece una conexión HTTPS"

```bash
sudo python3 main.py --protocolo tcp --puerto 443 -n 20
```

Abre una página HTTPS. Verás el "three-way handshake" de TCP: SYN → SYN ACK → ACK. Después verán paquetes PSH ACK con los datos cifrados.

### Caso 4: "Quiero monitorear una IP específica en mi red"

```bash
sudo python3 main.py --ip-origen 192.168.1.50
```

Reemplaza la IP con la del dispositivo que te interesa. Útil para ver qué está haciendo un teléfono, una smart TV o cualquier dispositivo de tu red.

### Caso 5: Guardar una captura para analizarla después

```bash
# En CSV (abre en Excel o pandas)
sudo python3 main.py -n 500 -o mi_captura.csv

# En texto plano
sudo python3 main.py -n 500 -o mi_captura.txt
```

### Caso 6: Solo quiero el resumen, sin ver paquete por paquete

```bash
sudo python3 main.py --modo-silencioso
```

Captura en silencio. Al presionar Ctrl+C muestra las estadísticas: protocolos más usados, IPs más activas, puertos más usados, etc.

### Caso 7: Diagnosticar si hay tráfico inesperado

```bash
# Capturar 1000 paquetes y ver el resumen de IPs
sudo python3 main.py -n 1000 --modo-silencioso
```

Si en las estadísticas aparecen IPs desconocidas haciendo muchas conexiones, puede indicar un proceso sospechoso o malware. (Siempre verifica antes de concluir — muchos servicios legítimos usan IPs poco conocidas.)

---

## Estructura del proyecto

El proyecto está dividido en módulos independientes. Cada archivo tiene una sola responsabilidad, lo que hace el código fácil de leer, modificar y extender.

```
netsniffer/
│
├── main.py                  ← Punto de entrada. Orquesta todos los módulos.
│                              Lee argumentos y los pasa a cada componente.
│
├── config/
│   └── configuracion.py     ← Un solo objeto con toda la configuración de sesión.
│                              Evita variables globales dispersas.
│
├── captura/
│   └── sniffer.py           ← Abre el raw socket y ejecuta el bucle principal.
│                              Recibe bytes crudos del sistema operativo.
│
├── parsers/
│   └── protocolos.py        ← Convierte bytes crudos en objetos Python.
│                              IPv4 → TCP / UDP / ICMP con dataclasses.
│
├── filtros/
│   └── motor.py             ← Decide si un paquete debe mostrarse o ignorarse.
│                              Fácil de extender con nuevos criterios.
│
├── estadisticas/
│   └── monitor.py           ← Acumula contadores durante la sesión.
│                              Top IPs, top puertos, bytes, paquetes por segundo.
│
├── interfaz/
│   └── terminal.py          ← Todo lo visual: banner, colores, tabla, resumen.
│                              Soporta Windows (VT100), Linux, macOS y ASCII fallback.
│
├── salida/
│   └── escritor.py          ← Escribe paquetes a disco en TXT o CSV.
│                              Patrón Factory: fácil agregar JSON, PCAP-texto, etc.
│
└── utils/
    └── permisos.py          ← Verifica privilegios de administrador al inicio.
                               Da un mensaje claro si faltan permisos.
```

### ¿Por qué esta estructura?

Separar el código en módulos con responsabilidades únicas (principio de responsabilidad única) tiene ventajas concretas:

- **Puedes cambiar la interfaz visual** sin tocar el parser ni los filtros
- **Puedes añadir un nuevo protocolo** sin romper nada de lo que ya funciona
- **Puedes probar cada módulo de forma aislada** escribiendo tests unitarios
- **Puedes leer el código** porque cada archivo hace exactamente una cosa

---

## Guía de contribución y extensión

Esta sección es para quienes quieran agregar funcionalidades a NetSniffer. Está escrita paso a paso para que puedas hacerlo incluso si apenas estás aprendiendo Python.

### Añadir soporte para un nuevo protocolo (ej: ARP)

ARP (Address Resolution Protocol) mapea IPs a direcciones MAC. No es IPv4 puro, pero el principio es el mismo.

**Paso 1:** Abre `parsers/protocolos.py` y registra el nuevo protocolo:

```python
# En el diccionario NOMBRES_PROTO, añade:
NOMBRES_PROTO: dict[int, str] = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    # --- nuevo ---
    2:   "IGMP",  # ejemplo de protocolo nuevo
}
```

**Paso 2:** Crea una dataclass para el nuevo protocolo:

```python
@dataclass
class PaqueteIGMP:
    """Encabezado IGMP desempaquetado."""
    tipo: int
    tiempo_respuesta: int
    direccion_grupo: str
    payload: bytes = field(repr=False, default=b"")
```

**Paso 3:** Escribe la función de parseo:

```python
def _parsear_igmp(datos: bytes) -> Optional[PaqueteIGMP]:
    if len(datos) < 8:
        return None
    try:
        tipo, tiempo, _, grupo = struct.unpack("!BBH4s", datos[:8])
        return PaqueteIGMP(
            tipo=tipo,
            tiempo_respuesta=tiempo,
            direccion_grupo=socket.inet_ntoa(grupo),
            payload=datos[8:],
        )
    except struct.error:
        return None
```

**Paso 4:** Llámala en `parsear_ip`:

```python
# En la función parsear_ip, agrega:
elif protocolo_num == 2:   transporte = _parsear_igmp(datos_transporte)
```

**Paso 5:** En `interfaz/terminal.py`, agrega el color y el formato de la columna INFO:

```python
# En _color_protocolo:
"IGMP": C.MAGENTA,

# En _info_transporte:
if isinstance(t, PaqueteIGMP):
    return f"Grupo: {t.direccion_grupo}  tipo={t.tipo}"
```

### Añadir un nuevo filtro (ej: por TTL)

**Paso 1:** En `config/configuracion.py`, añade el campo:

```python
@dataclass
class Configuracion:
    ttl_maximo: Optional[int] = None  # filtrar paquetes con TTL > este valor
```

**Paso 2:** En `main.py`, añade el argumento de línea de comandos:

```python
parser.add_argument("--ttl-max", type=int, default=None,
                    help="Ignorar paquetes con TTL mayor a este valor.")
```

**Paso 3:** En `filtros/motor.py`, añade el método:

```python
def _filtro_ttl(self, paquete: PaqueteIP) -> bool:
    maximo = self._config.ttl_maximo
    if not maximo:
        return True
    return paquete.ttl <= maximo

# Y llámalo en aceptar():
def aceptar(self, paquete: PaqueteIP) -> bool:
    return (
        self._filtro_protocolo(paquete)
        and self._filtro_ip_origen(paquete)
        and self._filtro_ip_destino(paquete)
        and self._filtro_puerto(paquete)
        and self._filtro_ttl(paquete)  # <- nuevo
    )
```

### Añadir un nuevo formato de salida (ej: JSON)

**Paso 1:** En `salida/escritor.py`, crea la nueva clase:

```python
import json

class EscritorJSON(EscritorBase):
    """Escribe paquetes en formato JSON, uno por línea (JSONL)."""

    def __init__(self, ruta: str):
        self._archivo = open(ruta, "w", encoding="utf-8")

    def escribir(self, paquete: PaqueteIP, numero: int):
        registro = {
            "num":       numero,
            "hora":      time.strftime("%H:%M:%S"),
            "ip_origen": paquete.ip_origen,
            "ip_destino":paquete.ip_destino,
            "protocolo": paquete.protocolo_nombre,
            "ttl":       paquete.ttl,
            "bytes":     paquete.tamano_total,
        }
        self._archivo.write(json.dumps(registro) + "\n")
        self._archivo.flush()

    def cerrar(self):
        self._archivo.close()
```

**Paso 2:** Regístralo en la función `crear_escritor`:

```python
def crear_escritor(ruta):
    ext = os.path.splitext(ruta)[1].lower()
    if ext == ".csv":  return EscritorCSV(ruta)
    if ext == ".json": return EscritorJSON(ruta)  # <- nuevo
    return EscritorTXT(ruta)
```

### Proceso para contribuir al proyecto

1. Haz un fork del repositorio en GitHub
2. Crea una rama con un nombre descriptivo: `git checkout -b agregar-soporte-arp`
3. Haz tus cambios y pruébalos localmente
4. Escribe al menos un test básico en `tests/` (si existe la carpeta)
5. Abre un Pull Request describiendo qué hiciste y por qué

No necesitas ser experto. Las contribuciones bienvenidas incluyen:
- Correcciones de errores o typos
- Mejoras en los comentarios o documentación
- Soporte para nuevos protocolos
- Traducciones del README

---

## Solución de problemas

### Error: "Permission denied" o "Se necesitan privilegios"

**Causa:** Los raw sockets requieren permisos de administrador porque permiten leer tráfico de red de bajo nivel.

**Solución en Linux/macOS:**
```bash
sudo python3 main.py
```

**Solución en Windows:**
Haz clic derecho en PowerShell o CMD → "Ejecutar como administrador", luego:
```
python main.py
```

---

### Error: "No se puede encontrar la interfaz"

**Causa:** Especificaste una interfaz que no existe o tiene otro nombre.

**Solución:** Encuentra el nombre correcto de tu interfaz:

```bash
# Linux/macOS:
ip link show
# o:
ifconfig

# Windows (en CMD o PowerShell):
ipconfig
```

Busca el nombre de tu conexión (ej: `enp3s0`, `wlan0`, `eth0` en Linux; en Windows no se especifica interfaz, se detecta automáticamente).

---

### No aparecen paquetes en pantalla

**Posibles causas:**

1. **Hay filtros activos muy específicos.** Verifica que no hayas puesto una IP o puerto que no tiene tráfico activo. Prueba sin filtros primero: `sudo python3 main.py`

2. **La interfaz incorrecta.** Si tienes Wi-Fi y Ethernet, intenta con la interfaz correcta: `sudo python3 main.py -i wlan0`

3. **Tu sistema tiene un firewall muy estricto.** En algunos entornos corporativos o VMs el tráfico puede estar bloqueado a nivel de kernel.

---

### En Windows no se ven colores

NetSniffer intenta activar los colores automáticamente. Si no funciona:

**Opción 1:** Usa Windows Terminal (la terminal moderna de Windows 10/11) en lugar de CMD.

**Opción 2:** Instala colorama:
```
pip install colorama
```

**Opción 3:** Si usas un script o rediriges la salida a un archivo, usa `--sin-color`:
```
python main.py --sin-color -o captura.txt
```

---

### Los caracteres especiales (╔ █ ✔) salen como símbolos raros

**Causa:** Tu terminal usa una codificación de caracteres antigua (cp850, cp1252) que no soporta Unicode completo.

**Solución en Windows CMD:**
```
chcp 65001
python main.py
```
Esto cambia la codificación a UTF-8. Si no funciona, NetSniffer detectará automáticamente que no hay soporte Unicode y usará caracteres ASCII equivalentes (`+`, `=`, `#`).

---

### Error: `struct.error` o `socket.error`

**Causa:** Se capturó un paquete malformado o truncado. Esto es normal en redes activas.

**Comportamiento:** NetSniffer ignora automáticamente estos paquetes y continúa. No es necesario hacer nada.

---

### Captura demasiado tráfico, no puedo leer nada

Usa filtros para reducir el ruido:

```bash
# Solo un protocolo
sudo python3 main.py -p tcp

# Solo tráfico web
sudo python3 main.py --puerto 80
sudo python3 main.py --puerto 443

# Solo desde tu dispositivo local hacia internet
sudo python3 main.py --ip-origen 192.168.1.X

# Modo silencioso: captura todo pero solo muestra el resumen al final
sudo python3 main.py --modo-silencioso
```

---

## Licencia y uso ético

NetSniffer se distribuye bajo la **Licencia MIT**.

```
MIT License — Copyright (c) 2024 Omar Palomares Velasco

Se permite usar, copiar, modificar, fusionar, publicar, distribuir,
sublicenciar y vender copias del software, siempre que se incluya
este aviso de copyright en todas las copias.

EL SOFTWARE SE PROPORCIONA "TAL CUAL", SIN GARANTÍA DE NINGÚN TIPO.
```

### Uso responsable y ético

Esta herramienta es poderosa. Con ese poder viene responsabilidad.

**Está bien usar NetSniffer para:**
- Analizar el tráfico de **tu propia red** y **tus propios dispositivos**
- Aprender cómo funcionan los protocolos de red
- Diagnosticar problemas en redes donde tienes autorización
- Desarrollar y probar tus propias aplicaciones de red
- Investigación de seguridad en entornos controlados y con permiso

**No está bien usar NetSniffer para:**
- Capturar tráfico de redes ajenas sin autorización
- Interceptar comunicaciones privadas de otras personas
- Recopilar credenciales, contraseñas o datos personales de terceros
- Cualquier actividad que viole leyes locales o internacionales

Interceptar tráfico de red sin autorización es un delito en la mayoría de países. Úsalo con inteligencia, con ética y con respeto.

---

## Reconocimientos

### Autor

**Omar Palomares Velasco** — Creador y mantenedor principal.

Este proyecto nació de la convicción de que las herramientas de redes no tienen que ser intimidantes. NetSniffer fue construido pieza por pieza con el propósito de que cualquier persona — estudiante, desarrollador, curioso — pueda abrir el código y entender exactamente qué está pasando.

### Para la comunidad, por la comunidad

NetSniffer es un proyecto abierto. No pertenece a ninguna empresa ni tiene intereses comerciales. Pertenece a quien lo usa, a quien aprende con él y a quien lo mejora.

Si este proyecto te ayudó a entender algo nuevo sobre redes, ya cumplió su propósito. Si quieres devolverle algo a la comunidad: compártelo, mejóralo, o simplemente enséñale a alguien más cómo funciona.

### Tecnologías

Construido con Python puro — sin dependencias externas obligatorias. Las únicas librerías usadas (`socket`, `struct`, `ctypes`) son parte de la biblioteca estándar de Python.

---

*"Hecho con curiosidad y código abierto — para quienes quieren entender cómo funciona el mundo digital."*

**— Omar Palomares Velasco**