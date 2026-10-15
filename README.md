# VPN VIVA

> Cliente gráfico para VPN IPSec en Linux (`vpnc` + Tkinter) con estado en vivo, reconexión automática y guardado seguro de credenciales.
> *Graphical IPSec VPN client for Linux with live status, auto-reconnect and secure credential storage.*

Una ventana sencilla para conectarse a la VPN corporativa, que **te avisa cuando la conexión se cae** y **reconecta sola**. Nació de un script de terminal con `zenity` y evolucionó a una aplicación con monitoreo continuo.

<p align="center">
  <img src="img/login.png" width="250" alt="Pantalla de acceso">
  &nbsp;&nbsp;
  <img src="img/conectado.png" width="250" alt="Conectado">
  &nbsp;&nbsp;
  <img src="img/reconectando.png" width="250" alt="Reconectando">
</p>
<p align="center"><sub>Acceso &nbsp;·&nbsp; Conectado &nbsp;·&nbsp; Caída detectada y reconectando</sub></p>

---

## Características

- **Punto de estado en vivo:** verde (conectado), ámbar parpadeante (conectando o reconectando) y rojo (desconectado). También se refleja en el icono de la barra de tareas y en el título de la ventana, aunque esté minimizada.
- **Monitoreo y reconexión automática:** revisa la conexión cada 15 s. Si se cae, trae la ventana al frente, envía una notificación de escritorio y reintenta hasta 5 veces con espera creciente.
- **Credenciales seguras:** la contraseña se guarda en el **llavero del sistema** (GNOME Keyring / KWallet) vía `secret-tool`, nunca en un archivo de texto. Es opcional y solo se guarda tras una conexión exitosa.
- **Cambio de contraseña:** si cambia la contraseña corporativa, se actualiza desde la propia app. Si el servidor rechaza la clave al reconectar, **deja de reintentar** (para no bloquear la cuenta) y pide la nueva automáticamente.
- **Gateway bloqueado por defecto:** viene precargado y solo se puede editar si es necesario.
- **Ventana de estado:** usuario conectado, gateway, IP del túnel, tiempo de conexión (cronómetro) y número de reconexiones.
- **Retoma sesiones:** si cierras la app dejando la VPN activa, al abrirla de nuevo retoma el monitoreo.
- **Una sola instancia**, con log rotativo para diagnóstico.
- **Sin dependencias de Python externas:** solo biblioteca estándar y Tkinter.

<p align="center">
  <img src="img/notificaciones.png" width="330" alt="Notificaciones de escritorio al caerse y restablecerse la VPN">
</p>
<p align="center"><sub>Notificaciones de escritorio al caerse y restablecerse la conexión</sub></p>

---

## Requisitos

- Linux de la familia Debian: **Linux Mint** o **Ubuntu** (el instalador también incluye soporte para Fedora/RHEL con `dnf`, sin probar).
- Permisos de administrador (`sudo`).
- Python 3 con Tkinter.
- Los datos de tu VPN, que **este repositorio no incluye**: el **gateway** y el **secret IPSec** (grupo). Solicítalos al equipo de redes.

El instalador se encarga de instalar: `vpnc`, `python3-tk`, `libsecret-tools` y `libnotify-bin`.

---

## Instalación

### 1. Clonar el repositorio

```bash
git clone <URL-DEL-REPOSITORIO>
cd <carpeta-del-repositorio>
```

### 2. Configurar el gateway y el secret

Abre `vpn_viva.py` y completa estas dos constantes al inicio del archivo:

```python
SECRET = "PON_AQUI_EL_SECRET"
GATEWAY_DEFAULT = "xxx.xxx.xxx.xxx"
```

> **Importante:** no subas estos valores a un repositorio público. Para evitar un commit accidental de tu copia local puedes ejecutar:
> ```bash
> git update-index --skip-worktree vpn_viva.py
> ```

### 3. Ejecutar el instalador

```bash
bash instalar_launcher.sh
```

Pedirá la contraseña de tu equipo (al escribirla no se ve nada; es normal) y realiza tres etapas:

| Etapa | Qué hace |
|-------|----------|
| **1/3** | Instala los programas necesarios (`vpnc`, `python3-tk`, `libsecret-tools`, `libnotify-bin`). |
| **2/3** | Autoriza en `sudo` **solo** los comandos de la VPN, para no pedir la clave de administrador en cada conexión. La regla se valida con `visudo -c` antes de instalarse. |
| **3/3** | Copia la app a `~/.local/share/vpn-viva/`, crea el icono y el lanzador en el menú de aplicaciones y en el escritorio. |

### 4. Permitir lanzar el icono

Si al hacer doble clic en el icono del escritorio no abre o muestra una advertencia: **clic derecho → Permitir lanzar** (solo la primera vez). También puedes abrirla desde el menú de aplicaciones buscando **VPN VIVA**.

---

## Uso

1. Abre **VPN VIVA**.
2. Escribe tu **usuario** y **contraseña** corporativos. El gateway ya viene escrito; pulsa **Cambiar** solo si necesitas otro.
3. Marca **Recordar credenciales** si quieres guardarlas (no lo hagas en equipos compartidos).
4. Pulsa **Conectar**. Cuando el punto se ponga verde, estás conectado.

**Detalles útiles**

- Cerrar la ventana con la **X** la **minimiza**; la VPN sigue activa y monitoreada.
- **Desconectar** corta la VPN y detiene el monitor.
- **Cerrar app sin desconectar** deja la VPN activa pero **sin monitoreo** hasta que vuelvas a abrir la app.
- **Cambiar contraseña** actualiza la copia que usa la aplicación; **no** cambia tu contraseña en el servidor corporativo.

---

## Cómo funciona

```
┌────────────────────┐   hilo en segundo plano    ┌─────────────────────┐
│ Interfaz (Tkinter) │ ◄── eventos (cola) ─────── │ Monitor (watchdog)  │
│ estado, cronómetro │                            │ cada 15 s verifica: │
└─────────┬──────────┘                            │ · proceso vpnc      │
          │ conectar / desconectar                │ · interfaz tunviva  │
          ▼                                       │ · ping (opcional)   │
   sudo vpnc / vpnc-disconnect  ◄─── reconecta ── └─────────────────────┘
          │
          ▼
  /etc/vpnc/viva.conf  (se escribe, vpnc lo lee y se vacía de inmediato)
```

- **Caída segura vs. dudosa:** si el proceso `vpnc` muere o el túnel desaparece, actúa de inmediato. Si solo falla el ping opcional, espera 3 fallos seguidos para evitar falsas alarmas.
- **Detección propia de vpnc:** se configura `DPD idle timeout (our side) 60`, así vpnc detecta un servidor caído en ~60 s en lugar de los 300 s por defecto.
- **Interfaz con nombre fijo** (`tunviva`) para no chocar con otras VPN que usen `tun0`.
- **Cancelar a tiempo:** al desconectar manualmente se detiene primero el monitor, para que no reconecte lo que acabas de cortar.

### Archivos que crea

| Ruta | Contenido |
|------|-----------|
| `~/.local/share/vpn-viva/` | La aplicación instalada y su icono |
| `~/.config/vpn-viva/config.json` | Usuario, gateway personalizado (si lo hay) y si recordar. **Nunca la contraseña** |
| `~/.cache/vpn-viva/vpn.log` | Log rotativo (sin contraseñas) |
| `~/.cache/vpn-viva/session.json` | Sesión activa, para poder retomarla |
| `/etc/sudoers.d/vpn-viva` | Permiso `NOPASSWD` limitado a 4 comandos |

---

## Configuración avanzada

Parámetros al inicio de `vpn_viva.py`:

| Constante | Por defecto | Descripción |
|-----------|-------------|-------------|
| `VPN_IF` | `tunviva` | Nombre de la interfaz del túnel |
| `HEALTH_HOST` | `""` | IP interna alcanzable **solo por VPN**. Si se define, se usa ping a través del túnel para verificar que el tráfico realmente pasa. **Recomendado** |
| `CHECK_INTERVAL` | `15` | Segundos entre chequeos |
| `FAIL_THRESHOLD` | `3` | Pings fallidos seguidos para declarar la caída |
| `MAX_RETRIES` | `5` | Reintentos de reconexión antes de rendirse |
| `CONNECT_TIMEOUT` | `45` | Segundos máximos esperando a `vpnc` |
| `AUTH_ERROR_RE` | *(regex)* | Texto con el que `vpnc` reporta credenciales rechazadas. Si tu versión usa otro mensaje, revisa el log tras probar una clave incorrecta y ajústalo |

La paleta de colores también está en constantes (`BG`, `ACCENT`, `DANGER`, …).

---

## Seguridad

- La contraseña vive en el **llavero del sistema** (cifrado) y, durante una sesión, **solo en memoria**.
- El archivo `/etc/vpnc/viva.conf` se escribe con permisos `600` y se **vacía inmediatamente** después de que `vpnc` lo lee.
- El permiso en `sudo` cubre únicamente `vpnc`, `vpnc-disconnect` y la escritura de ese archivo de configuración.
- El gateway se valida (solo letras, números, puntos y guiones) antes de escribirse en la configuración.
- Ante una clave rechazada **no se reintenta**, para no bloquear la cuenta corporativa.
- El log no contiene contraseñas.
- **Este repositorio no incluye el gateway ni el secret IPSec.** No los subas.

---

## Solución de problemas

| Problema | Qué hacer |
|----------|-----------|
| El icono no abre | Clic derecho → **Permitir lanzar**. Si sigue igual, ejecuta `python3 ~/.local/share/vpn-viva/vpn_viva.py` en una terminal para ver el error |
| `No module named tkinter` | `sudo apt install -y python3-tk` |
| "revise el sudoers" | Falló la etapa 2 de la instalación; vuelve a ejecutar `bash instalar_launcher.sh` |
| No guarda credenciales | Verifica que `libsecret-tools` esté instalado y que el llavero de la sesión esté desbloqueado |
| Dice que ya está abierta | Hay otra ventana abierta o minimizada; búscala en la barra de tareas |
| No conecta | Revisa tu internet y el log: `~/.cache/vpn-viva/vpn.log` |

---

## Desinstalar

Primero abre la app y pulsa **Olvidar credenciales** (si las guardaste). Luego:

```bash
rm -r ~/.local/share/vpn-viva
rm ~/.local/share/applications/vpn-viva.desktop
rm ~/.config/vpn-viva/config.json
sudo rm /etc/sudoers.d/vpn-viva
```

Y borra el icono **VPN VIVA** del escritorio.

---

## Estructura del repositorio

```
.
├── vpn_viva.py            # Aplicación (interfaz + monitor + reconexión)
├── instalar_launcher.sh   # Instalador: dependencias, permisos y lanzador
├── docs/
│   └── img/               # Capturas de pantalla de este README
└── README.md
```

---

## Autoría

Creado por **Franklyn Castro**.

**Menciones especiales:** Deivy Borge & Francisco Brujan.

---

<sub>Herramienta de uso interno entregada tal cual. No incluye credenciales ni datos de conexión; el gateway y el secret IPSec deben ser provistos por el equipo de redes correspondiente.</sub>
