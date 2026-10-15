#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN VIVA (IPSec / vpnc) - Cliente gráfico con monitoreo y reconexión automática.
Autor: Franklyn Yawerlyn Castro. 
Menciones especiales, Francisco Brujar & Deibi Borges.

DEPENDENCIAS
  Debian/Ubuntu/Mint: sudo apt install -y vpnc python3-tk libsecret-tools libnotify-bin
  Fedora/RHEL/CentOS: sudo dnf install -y vpnc python3-tkinter libsecret libnotify
  (libsecret-tools -> guardar credenciales de forma segura | libnotify -> avisos de escritorio)

SUDOERS (igual que antes; ejecute 'sudo visudo' y reemplace 'usuario'):
  usuario ALL=(ALL) NOPASSWD: /usr/sbin/vpnc, /usr/sbin/vpnc-disconnect, /usr/bin/tee /etc/vpnc/viva.conf, /usr/bin/chmod 600 /etc/vpnc/viva.conf

USO
  python3 vpn_viva.py
"""

import fcntl
import json
import logging
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from tkinter import messagebox

# ==============================================================================
# CONFIGURACIÓN
# ==============================================================================
APP_NAME = "VPN VIVA"
CONFIG_FILE = "/etc/vpnc/viva.conf"
SECRET ="8@95X0gb7r*ok"
GATEWAY_DEFAULT = "190.8.37.86"

VPN_IF = "tunviva"       # Nombre fijo de la interfaz del túnel
HEALTH_HOST = ""         # IP interna alcanzable SOLO por VPN (vacío = no hacer ping)
CHECK_INTERVAL = 15      # Segundos entre chequeos
FAIL_THRESHOLD = 3       # Pings fallidos seguidos para declarar caída
MAX_RETRIES = 5          # Reintentos de reconexión antes de rendirse
CONNECT_TIMEOUT = 45     # Segundos máximos esperando a vpnc

KEYRING_SERVICE = "vpn-viva"
CFG_DIR = os.path.expanduser("~/.config/vpn-viva")
STATE_DIR = os.path.expanduser("~/.cache/vpn-viva")
CFG_PATH = os.path.join(CFG_DIR, "config.json")
SESSION_PATH = os.path.join(STATE_DIR, "session.json")
LOCK_PATH = os.path.join(STATE_DIR, "app.lock")
LOG_PATH = os.path.join(STATE_DIR, "vpn.log")

# Texto con el que vpnc suele reportar credenciales rechazadas. Si su versión
# usa otro mensaje, revise el log tras probar una clave incorrecta y ajústelo.
AUTH_ERROR_RE = re.compile(
    r"authentication unsuccessful|auth\w*.*(fail|denied|reject)|xauth.*(fail|denied)|invalid (user|password)",
    re.I,
)

# --- Paleta: gris-azulado medio, ni oscuro ni claro ---------------------------
BG = "#5B6D84"
LINE = "#7A8CA3"
TXT = "#F4F7FA"
MUTED = "#DCE4EC"
ENTRY_BG = "#EEF2F6"
ENTRY_FG = "#1F2A37"
ENTRY_LOCK = "#8E9DB1"
ENTRY_OFF = "#C9D3DF"
ACCENT, ACCENT_H = "#2B6FD0", "#3C82E0"
DANGER, DANGER_H = "#C94A45", "#D95B56"
BTN_OFF = "#7F8FA4"
OK, WARN, WARN_DIM, OFF = "#3DDC84", "#F5B942", "#A88A45", "#E5534B"
ERR_TXT = "#FFD3CF"

# Estados de la aplicación
DESCONECTADO, CONECTANDO, CONECTADO, RECONECTANDO, DESCONECTANDO = (
    "desconectado", "conectando", "conectado", "reconectando", "desconectando")

ESTADOS = {
    DESCONECTADO: ("Desconectado", OFF, f"{APP_NAME} · Desconectado"),
    CONECTANDO: ("Conectando…", WARN, f"{APP_NAME} · Conectando…"),
    CONECTADO: ("Conectado", OK, f"{APP_NAME} · Conectado"),
    RECONECTANDO: ("Sin conexión · reconectando…", WARN, f"{APP_NAME} · Reconectando…"),
    DESCONECTANDO: ("Desconectando…", WARN, f"{APP_NAME} · Desconectando…"),
}

log = logging.getLogger("vpn-viva")


def configurar_log():
    os.makedirs(STATE_DIR, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    h = RotatingFileHandler(LOG_PATH, maxBytes=200_000, backupCount=2, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"))
    log.addHandler(h)
    log.setLevel(logging.INFO)


# ==============================================================================
# DATOS: ajustes, llavero seguro y sesión
# ==============================================================================
@dataclass
class Sesion:
    usuario: str
    clave: str
    gateway: str


class Ajustes:
    """Datos NO secretos (usuario, gateway, si recordar). La clave nunca va aquí."""

    def __init__(self):
        os.makedirs(CFG_DIR, exist_ok=True)
        os.chmod(CFG_DIR, 0o700)
        self.data = {"usuario": "", "gateway": "", "recordar": False}
        try:
            with open(CFG_PATH, encoding="utf-8") as f:
                self.data.update(json.load(f))
        except (OSError, ValueError):
            pass

    def guardar(self):
        tmp = CFG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CFG_PATH)


class Llavero:
    """Contraseña en el llavero del sistema (GNOME Keyring/KWallet) vía secret-tool."""

    @staticmethod
    def disponible():
        return shutil.which("secret-tool") is not None

    @staticmethod
    def guardar(usuario, clave):
        try:
            r = subprocess.run(
                ["secret-tool", "store", f"--label={APP_NAME}", "service", KEYRING_SERVICE, "user", usuario],
                input=clave, text=True, capture_output=True, timeout=30)
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def leer(usuario):
        if not Llavero.disponible() or not usuario:
            return None
        try:
            r = subprocess.run(
                ["secret-tool", "lookup", "service", KEYRING_SERVICE, "user", usuario],
                capture_output=True, text=True, timeout=30)
            return r.stdout.rstrip("\n") if r.returncode == 0 and r.stdout else None
        except (OSError, subprocess.TimeoutExpired):
            return None

    @staticmethod
    def borrar(usuario):
        if Llavero.disponible() and usuario:
            try:
                subprocess.run(["secret-tool", "clear", "service", KEYRING_SERVICE, "user", usuario],
                               capture_output=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                pass


def guardar_sesion(s, desde):
    """Recuerda qué sesión está activa para poder retomarla si la app se reinicia."""
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = SESSION_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"usuario": s.usuario, "gateway": s.gateway, "desde": desde}, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SESSION_PATH)


def leer_sesion():
    try:
        with open(SESSION_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def borrar_sesion():
    try:
        os.remove(SESSION_PATH)
    except OSError:
        pass


# ==============================================================================
# OPERACIONES DE VPN (sudo + vpnc)
# ==============================================================================
def sudo(*args, entrada=None, timeout=None, silencio_stdout=False):
    # -n: nunca pedir clave de sudo (si falta el sudoers, falla en vez de colgarse)
    return subprocess.run(
        ["sudo", "-n", *args], input=entrada, text=True, timeout=timeout,
        stdout=subprocess.DEVNULL if silencio_stdout else subprocess.PIPE,
        stderr=subprocess.PIPE)


def escribir_config(texto):
    sudo("chmod", "600", CONFIG_FILE)   # si ya existe, cerrar permisos ANTES de escribir
    r = sudo("tee", CONFIG_FILE, entrada=texto, silencio_stdout=True)
    if r.returncode != 0:
        return False
    sudo("chmod", "600", CONFIG_FILE)
    return True


def limpiar_config():
    sudo("tee", CONFIG_FILE, entrada="\n", silencio_stdout=True)


def conectar_vpn(s):
    """Devuelve (ok, salida). Las credenciales viven en disco solo mientras vpnc las lee."""
    texto = (
        f"IPSec gateway {s.gateway}\nIPSec ID {s.gateway}\nIPSec secret {SECRET}\n"
        f"Xauth username {s.usuario}\nXauth password {s.clave}\n"
        "IKE DH Group dh14\nPerfect Forward Secrecy dh14\nNAT Traversal Mode force-natt\n"
        f"Interface name {VPN_IF}\nDPD idle timeout (our side) 60\n")
    try:
        if not escribir_config(texto):
            return False, "No se pudo escribir la configuración (revise el sudoers)."
        # La salida va a un archivo temporal (no a una pipe): vpnc se demoniza y podría
        # dejar la pipe abierta, lo que colgaría la lectura.
        with tempfile.TemporaryFile("w+") as out:
            r = subprocess.run(["sudo", "-n", "vpnc", CONFIG_FILE, "--non-inter"],
                               stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                               timeout=CONNECT_TIMEOUT)
            out.seek(0)
            return r.returncode == 0, out.read().strip()
    except subprocess.TimeoutExpired:
        return False, "Tiempo de espera agotado esperando a vpnc."
    except OSError as e:
        return False, str(e)
    finally:
        limpiar_config()


def desconectar_vpn():
    sudo("vpnc-disconnect", silencio_stdout=True)
    limpiar_config()


def vpn_proceso_activo():
    return subprocess.run(["pgrep", "-x", "vpnc"], stdout=subprocess.DEVNULL).returncode == 0


def tunel_existe():
    return os.path.exists(f"/sys/class/net/{VPN_IF}")


def ip_tunel():
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", VPN_IF],
                             capture_output=True, text=True, timeout=3).stdout
        m = re.search(r"inet\s+([\d.]+)", out)
        return m.group(1) if m else "—"
    except (OSError, subprocess.TimeoutExpired):
        return "—"


def vpn_saludable():
    if not vpn_proceso_activo() or not tunel_existe():
        return False
    if HEALTH_HOST:
        r = subprocess.run(["ping", "-c", "1", "-W", "2", "-I", VPN_IF, HEALTH_HOST],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    return True


def es_error_auth(salida):
    return bool(salida and AUTH_ERROR_RE.search(salida))


def notificar(titulo, mensaje, urgente=False):
    if shutil.which("notify-send"):
        subprocess.Popen(["notify-send", "-u", "critical" if urgente else "normal", "-a", APP_NAME,
                          titulo, mensaje], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def fmt_tiempo(seg):
    h, r = divmod(max(int(seg), 0), 3600)
    m, s = divmod(r, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


# ==============================================================================
# INTERFAZ
# ==============================================================================
class App:
    ANCHO = 390

    def __init__(self, root):
        self.root = root
        self.ajustes = Ajustes()
        self.estado = DESCONECTADO
        self.sesion = None
        self.conectado_desde = None
        self.caida_desde = None
        self.hora_caida = ""
        self.reconexiones = 0
        self.eventos = queue.Queue()
        self.detener = threading.Event()
        self.hilo = None
        self.reconectar_despues = False
        self.gw_abierto = False
        self.pulso = False
        self._ip_t = 0.0

        self._fuentes()
        self._iconos()
        self._construir()
        self._precargar_credenciales()
        self._adoptar_sesion()
        self._aplicar_estado()

        root.protocol("WM_DELETE_WINDOW", self._al_cerrar)
        root.after(200, self._procesar_eventos)
        root.after(1000, self._tick)
        root.after(500, self._animar)

    # ---------------------------------------------------------------- estilo
    def _fuentes(self):
        fam = tkfont.nametofont("TkDefaultFont").actual("family")
        mono = tkfont.nametofont("TkFixedFont").actual("family")

        def mk(size, **kw):
            return tkfont.Font(self.root, family=fam, size=size, **kw)
        self.f_titulo = mk(19, weight="bold")
        self.f_estado = mk(11, weight="bold")
        self.f_etq = mk(9)
        self.f_entry = mk(11)
        self.f_btn = mk(11, weight="bold")
        self.f_link = mk(9, underline=True)
        self.f_valor = mk(10, weight="bold")
        self.f_timer = tkfont.Font(self.root, family=mono, size=22, weight="bold")

    def _crear_icono(self, color):
        img = tk.PhotoImage(width=32, height=32)
        cx = cy = 15.5
        r = 13
        for y in range(32):
            dx2 = r * r - (y - cy) ** 2
            if dx2 < 0:
                continue
            dx = int(dx2 ** 0.5)
            x0, x1 = int(cx - dx), int(cx + dx)
            img.put("{" + " ".join([color] * (x1 - x0 + 1)) + "}", to=(x0, y))
        return img

    def _iconos(self):
        # Icono de la ventana/barra de tareas: un punto del color del estado
        self.iconos = {c: self._crear_icono(c) for c in (OK, WARN, OFF)}

    def _etq(self, padre, texto):
        return tk.Label(padre, text=texto, font=self.f_etq, fg=MUTED, bg=BG)

    def _entry(self, padre, var, show=None):
        return tk.Entry(padre, textvariable=var, show=show, font=self.f_entry, relief="flat",
                        bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG,
                        readonlybackground=ENTRY_LOCK, disabledbackground=ENTRY_OFF,
                        disabledforeground="#4B5563", highlightthickness=2,
                        highlightbackground=BG, highlightcolor=ACCENT)

    def _boton(self, padre, texto, comando, color, hover):
        b = tk.Button(padre, text=texto, command=comando, bg=color, fg=TXT, font=self.f_btn,
                      activebackground=hover, activeforeground=TXT, disabledforeground="#DDE4EC",
                      relief="flat", bd=0, highlightthickness=0, cursor="hand2", pady=10)
        b.color, b.hover = color, hover
        b.bind("<Enter>", lambda e: b["state"] == "normal" and b.config(bg=b.hover))
        b.bind("<Leave>", lambda e: b["state"] == "normal" and b.config(bg=b.color))
        return b

    def _set_boton(self, b, habilitado, texto=None):
        if texto is not None:
            b.config(text=texto)
        b.config(state="normal" if habilitado else "disabled",
                 bg=b.color if habilitado else BTN_OFF,
                 cursor="hand2" if habilitado else "arrow")

    def _link(self, padre, texto, comando):
        lb = tk.Label(padre, text=texto, font=self.f_link, fg=MUTED, bg=BG, cursor="hand2")
        lb.bind("<Button-1>", lambda e: comando())
        lb.bind("<Enter>", lambda e: lb.config(fg=TXT))
        lb.bind("<Leave>", lambda e: lb.config(fg=MUTED))
        return lb

    def _fila_info(self, padre, etiqueta):
        f = tk.Frame(padre, bg=BG)
        f.pack(fill="x", pady=3)
        self._etq(f, etiqueta).pack(side="left")
        v = tk.Label(f, text="—", font=self.f_valor, fg=TXT, bg=BG)
        v.pack(side="right")
        return v

    # ---------------------------------------------------------- construcción
    def _construir(self):
        r = self.root
        r.configure(bg=BG)
        r.resizable(False, False)
        px = 28

        cab = tk.Frame(r, bg=BG)
        cab.pack(fill="x", padx=px, pady=(24, 6))
        tk.Label(cab, text="VPN VIVA", font=self.f_titulo, fg=TXT, bg=BG).pack(anchor="w")
        self._etq(cab, "Acceso corporativo seguro").pack(anchor="w")

        est = tk.Frame(r, bg=BG)
        est.pack(fill="x", padx=px, pady=(12, 14))
        self.dot = tk.Canvas(est, width=16, height=16, bg=BG, highlightthickness=0)
        self.dot_id = self.dot.create_oval(2, 2, 14, 14, fill=OFF, outline="")
        self.dot.pack(side="left")
        self.lbl_estado = tk.Label(est, text="", font=self.f_estado, fg=TXT, bg=BG)
        self.lbl_estado.pack(side="left", padx=8)

        tk.Frame(r, height=1, bg=LINE).pack(fill="x", padx=px)
        self.cont = tk.Frame(r, bg=BG)
        self.cont.pack(fill="x", padx=px, pady=(16, 22))

        self._construir_login()
        self._construir_conectado()

    def _construir_login(self):
        v = self.v_login = tk.Frame(self.cont, bg=BG)
        self.var_user = tk.StringVar()
        self.var_pass = tk.StringVar()
        self.var_gw = tk.StringVar(value=self.ajustes.data.get("gateway") or GATEWAY_DEFAULT)
        self.var_recordar = tk.BooleanVar(value=bool(self.ajustes.data.get("recordar")))

        self._etq(v, "Usuario").pack(anchor="w")
        self.e_user = self._entry(v, self.var_user)
        self.e_user.pack(fill="x", ipady=6, pady=(4, 12))

        self._etq(v, "Contraseña").pack(anchor="w")
        self.e_pass = self._entry(v, self.var_pass, show="•")
        self.e_pass.pack(fill="x", ipady=6, pady=(4, 12))

        fila = tk.Frame(v, bg=BG)
        fila.pack(fill="x")
        self._etq(fila, "Gateway (servidor)").pack(side="left")
        self.lnk_gw = self._link(fila, "Cambiar", self._toggle_gw)
        self.lnk_gw.pack(side="right")
        self.e_gw = self._entry(v, self.var_gw)
        self.e_gw.pack(fill="x", ipady=6, pady=(4, 12))

        self.chk = tk.Checkbutton(
            v, text="Recordar credenciales (llavero seguro)", variable=self.var_recordar,
            font=self.f_etq, fg=TXT, bg=BG, activebackground=BG, activeforeground=TXT,
            selectcolor=ACCENT, highlightthickness=0, bd=0, anchor="w", cursor="hand2")
        self.chk.pack(fill="x", pady=(2, 0))
        self.lbl_sin_llavero = self._etq(v, "Instale libsecret-tools para poder guardar credenciales.")
        if not Llavero.disponible():
            self.var_recordar.set(False)
            self.chk.config(state="disabled", cursor="arrow")
            self.lbl_sin_llavero.pack(anchor="w")

        self.btn_conectar = self._boton(v, "Conectar", self._click_conectar, ACCENT, ACCENT_H)
        self.btn_conectar.pack(fill="x", pady=(14, 8))

        self.lbl_error = tk.Label(v, text="", font=self.f_etq, fg=ERR_TXT, bg=BG,
                                  wraplength=self.ANCHO - 70, justify="left")
        self.lbl_error.pack(anchor="w")

        self.fila_links = tk.Frame(v, bg=BG)
        self.fila_links.pack(fill="x", pady=(6, 0))
        self.lnk_cambiar = self._link(self.fila_links, "Cambiar contraseña guardada",
                                      lambda: self._dialogo_clave())
        self.lnk_olvidar = self._link(self.fila_links, "Olvidar credenciales", self._olvidar)

        for w in (self.e_user, self.e_pass, self.e_gw):
            w.bind("<Return>", self._click_conectar)

    def _construir_conectado(self):
        v = self.v_conectado = tk.Frame(self.cont, bg=BG)
        self.i_usuario = self._fila_info(v, "Usuario")
        self.i_gw = self._fila_info(v, "Gateway")
        self.i_ip = self._fila_info(v, "IP del túnel")
        self.i_recon = self._fila_info(v, "Reconexiones")

        tk.Frame(v, height=1, bg=LINE).pack(fill="x", pady=(12, 10))
        self.lbl_caption = self._etq(v, "Tiempo conectado")
        self.lbl_caption.pack(anchor="w")
        self.lbl_timer = tk.Label(v, text="00:00:00", font=self.f_timer, fg=TXT, bg=BG)
        self.lbl_timer.pack(anchor="w", pady=(2, 4))
        self.lbl_aviso = tk.Label(v, text="", font=self.f_etq, fg=WARN, bg=BG, justify="left",
                                  wraplength=self.ANCHO - 70)
        self.lbl_aviso.pack(anchor="w")

        self.btn_desc = self._boton(v, "Desconectar", self._click_desconectar, DANGER, DANGER_H)
        self.btn_desc.pack(fill="x", pady=(14, 8))

        fl = tk.Frame(v, bg=BG)
        fl.pack(fill="x", pady=(6, 0))
        self._link(fl, "Cambiar contraseña", lambda: self._dialogo_clave()).pack(side="left")
        self._link(fl, "Cerrar app sin desconectar", self._salir_dejando_vpn).pack(side="right")

    # ----------------------------------------------------------- estado / UI
    def _aplicar_estado(self):
        texto, color, titulo = ESTADOS[self.estado]
        self.lbl_estado.config(text=texto)
        self.dot.itemconfig(self.dot_id, fill=color)
        self.root.title(titulo)
        self.root.iconphoto(True, self.iconos[color])

        if self.estado in (DESCONECTADO, CONECTANDO):
            self.v_conectado.pack_forget()
            self.v_login.pack(fill="x")
            libre = self.estado == DESCONECTADO
            st = "normal" if libre else "disabled"
            self.e_user.config(state=st)
            self.e_pass.config(state=st)
            self.e_gw.config(state="normal" if (libre and self.gw_abierto) else "readonly")
            self._set_boton(self.btn_conectar, libre, "Conectar" if libre else "Conectando…")
            self._refrescar_links()
        else:
            self.v_login.pack_forget()
            self.v_conectado.pack(fill="x")
            self._refrescar_info()
            if self.estado == CONECTADO:
                self.lbl_caption.config(text="Tiempo conectado")
                self._set_boton(self.btn_desc, True, "Desconectar")
            elif self.estado == RECONECTANDO:
                self.lbl_caption.config(text="Sin conexión desde hace")
                self._set_boton(self.btn_desc, True, "Cancelar y desconectar")
            else:
                self._set_boton(self.btn_desc, False, "Desconectando…")
            if self.estado != RECONECTANDO:
                self.lbl_aviso.config(text="", fg=WARN)

        self.root.update_idletasks()
        self.root.geometry(f"{self.ANCHO}x{self.root.winfo_reqheight()}")

    def _refrescar_links(self):
        for w in (self.lnk_cambiar, self.lnk_olvidar):
            w.pack_forget()
        if self.ajustes.data.get("recordar") and Llavero.disponible():
            self.lnk_cambiar.pack(side="left")
            self.lnk_olvidar.pack(side="right")

    def _refrescar_info(self):
        s = self.sesion
        self.i_usuario.config(text=s.usuario if s else "—")
        self.i_gw.config(text=s.gateway if s else "—")
        self.i_ip.config(text=ip_tunel() if self.estado == CONECTADO else "—")
        self.i_recon.config(text=str(self.reconexiones))
        self._ip_t = time.time()

    def _tick(self):
        ahora = time.time()
        if self.estado == CONECTADO and self.conectado_desde:
            self.lbl_timer.config(text=fmt_tiempo(ahora - self.conectado_desde))
            if ahora - self._ip_t > 10:
                self.i_ip.config(text=ip_tunel())
                self._ip_t = ahora
        elif self.estado == RECONECTANDO and self.caida_desde:
            self.lbl_timer.config(text=fmt_tiempo(ahora - self.caida_desde))
        self.root.after(1000, self._tick)

    def _animar(self):
        if self.estado in (CONECTANDO, RECONECTANDO, DESCONECTANDO):
            self.pulso = not self.pulso
            self.dot.itemconfig(self.dot_id, fill=WARN if self.pulso else WARN_DIM)
        self.root.after(500, self._animar)

    def _mostrar_error(self, msg):
        self.lbl_error.config(text=msg)
        self.root.update_idletasks()
        self.root.geometry(f"{self.ANCHO}x{self.root.winfo_reqheight()}")

    def _traer_al_frente(self):
        self.root.deiconify()
        self.root.lift()

    # --------------------------------------------------------------- gateway
    def _toggle_gw(self):
        if self.estado != DESCONECTADO:
            return
        self.gw_abierto = not self.gw_abierto
        if self.gw_abierto:
            self.lnk_gw.config(text="Restablecer")
            self.e_gw.config(state="normal")
            self.e_gw.focus_set()
            self.e_gw.icursor("end")
        else:
            self.var_gw.set(GATEWAY_DEFAULT)
            self.lnk_gw.config(text="Cambiar")
            self.e_gw.config(state="readonly")

    # ------------------------------------------------------- credenciales
    def _precargar_credenciales(self):
        d = self.ajustes.data
        self.var_user.set(d.get("usuario", ""))
        if d.get("recordar") and Llavero.disponible():
            clave = Llavero.leer(d.get("usuario", ""))
            if clave:
                self.var_pass.set(clave)
            else:
                d["recordar"] = False
                self.var_recordar.set(False)
        if d.get("gateway"):
            self.gw_abierto = False

    def _guardar_preferencias(self, s):
        d = self.ajustes.data
        previo = d.get("usuario", "")
        d["usuario"] = s.usuario
        d["gateway"] = "" if s.gateway == GATEWAY_DEFAULT else s.gateway
        if self.var_recordar.get() and Llavero.disponible():
            if Llavero.guardar(s.usuario, s.clave):
                d["recordar"] = True
                if previo and previo != s.usuario:
                    Llavero.borrar(previo)
            else:
                d["recordar"] = False
                self.var_recordar.set(False)
                messagebox.showwarning(
                    APP_NAME, "No se pudieron guardar las credenciales en el llavero.\n"
                              "Verifique que el llavero del sistema esté desbloqueado.")
        else:
            Llavero.borrar(s.usuario)
            d["recordar"] = False
        self.ajustes.guardar()

    def _olvidar(self):
        usuario = self.var_user.get().strip() or self.ajustes.data.get("usuario", "")
        if not messagebox.askyesno(APP_NAME, "¿Borrar la contraseña guardada de este equipo?"):
            return
        Llavero.borrar(usuario)
        self.ajustes.data["recordar"] = False
        self.ajustes.guardar()
        self.var_recordar.set(False)
        self.var_pass.set("")
        self._refrescar_links()
        self._mostrar_error("")

    def _dialogo_clave(self, reconectar_tras=False):
        usuario = self.sesion.usuario if self.sesion else self.var_user.get().strip()
        if not usuario:
            messagebox.showwarning(APP_NAME, "Escriba primero su usuario.")
            return
        top = tk.Toplevel(self.root)
        top.title("Cambiar contraseña")
        top.configure(bg=BG)
        top.resizable(False, False)
        top.transient(self.root)
        marco = tk.Frame(top, bg=BG)
        marco.pack(padx=28, pady=22)

        tk.Label(marco, text="Cambiar contraseña", font=self.f_estado, fg=TXT, bg=BG).pack(anchor="w")
        tk.Label(marco, font=self.f_etq, fg=MUTED, bg=BG, justify="left", wraplength=320,
                 text=f"Usuario: {usuario}\nActualiza la contraseña que usa esta aplicación "
                      "(la guardada y la de las reconexiones). Si cambió su contraseña corporativa, "
                      "escriba aquí la nueva.").pack(anchor="w", pady=(4, 12))
        v1, v2 = tk.StringVar(), tk.StringVar()
        self._etq(marco, "Nueva contraseña").pack(anchor="w")
        e1 = self._entry(marco, v1, show="•")
        e1.pack(fill="x", ipady=6, pady=(4, 10))
        self._etq(marco, "Confirmar contraseña").pack(anchor="w")
        e2 = self._entry(marco, v2, show="•")
        e2.pack(fill="x", ipady=6, pady=(4, 8))
        lbl = tk.Label(marco, text="", font=self.f_etq, fg=ERR_TXT, bg=BG)
        lbl.pack(anchor="w")

        def guardar(_e=None):
            a, b = v1.get(), v2.get()
            if not a:
                lbl.config(text="Escriba la nueva contraseña.")
            elif a != b:
                lbl.config(text="Las contraseñas no coinciden.")
            else:
                top.destroy()
                self._aplicar_nueva_clave(usuario, a, reconectar_tras)

        self._boton(marco, "Guardar", guardar, ACCENT, ACCENT_H).pack(fill="x", pady=(8, 6))
        self._link(marco, "Cancelar", top.destroy).pack()
        top.bind("<Return>", guardar)
        top.bind("<Escape>", lambda e: top.destroy())

        top.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - top.winfo_reqwidth()) // 2
        top.geometry(f"+{max(x, 0)}+{self.root.winfo_rooty() + 40}")
        top.wait_visibility()
        top.grab_set()
        e1.focus_set()

    def _aplicar_nueva_clave(self, usuario, nueva, reconectar_tras):
        self.var_pass.set(nueva)
        if self.sesion:
            self.sesion.clave = nueva        # el monitor usará la nueva en su próxima reconexión
        if self.ajustes.data.get("recordar") and Llavero.disponible():
            if not Llavero.guardar(usuario, nueva):
                messagebox.showwarning(APP_NAME, "No se pudo actualizar el llavero del sistema.")
        log.info("Contraseña actualizada por el usuario (%s)", usuario)
        if reconectar_tras and self.estado == DESCONECTADO:
            self._click_conectar()
        elif self.estado in (CONECTADO, RECONECTANDO):
            if messagebox.askyesno(APP_NAME, "Contraseña actualizada.\n\n¿Reconectar ahora para "
                                             "validar la nueva contraseña?"):
                self.reconectar_despues = True
                self._desconectar()

    # ------------------------------------------------------------- acciones
    def _click_conectar(self, _e=None):
        if self.estado != DESCONECTADO:
            return
        usuario = self.var_user.get().strip()
        clave = self.var_pass.get()
        gw = self.var_gw.get().strip() or GATEWAY_DEFAULT
        if not usuario or not clave:
            self._mostrar_error("Ingrese usuario y contraseña.")
            return
        if not re.fullmatch(r"[A-Za-z0-9.\-]+", gw):
            self._mostrar_error("El gateway solo puede contener letras, números, puntos y guiones.")
            return
        self._mostrar_error("")
        self.sesion = Sesion(usuario, clave, gw)
        self.estado = CONECTANDO
        self._aplicar_estado()
        log.info("Conectando a %s como %s", gw, usuario)
        threading.Thread(target=self._hilo_conectar, args=(self.sesion,), daemon=True).start()

    def _hilo_conectar(self, s):
        ok, salida = conectar_vpn(s)
        self.eventos.put(("conexion_ok",) if ok else ("conexion_error", salida))

    def _click_desconectar(self):
        if self.estado in (CONECTADO, RECONECTANDO):
            self._desconectar()

    def _desconectar(self):
        self.detener.set()                   # PRIMERO el monitor, para que no reconecte
        self.estado = DESCONECTANDO
        self._aplicar_estado()
        threading.Thread(target=self._hilo_desconectar, args=(self.hilo,), daemon=True).start()

    def _hilo_desconectar(self, hilo):
        if hilo and hilo.is_alive():
            hilo.join(timeout=CONNECT_TIMEOUT + 15)
        desconectar_vpn()
        borrar_sesion()
        log.info("Desconexión manual")
        self.eventos.put(("desconectado",))

    def _al_cerrar(self):
        if self.estado == DESCONECTADO:
            self.root.destroy()
        else:
            self.root.iconify()              # minimizar: el monitor sigue activo

    def _salir_dejando_vpn(self):
        if messagebox.askyesno(
                APP_NAME, "La VPN seguirá activa, pero SIN monitoreo ni reconexión automática "
                          "mientras la aplicación esté cerrada.\n\nAl abrirla de nuevo retomará la "
                          "sesión.\n\n¿Cerrar la aplicación?"):
            self.detener.set()
            self.root.destroy()

    # --------------------------------------------------------- sesión previa
    def _adoptar_sesion(self):
        """Si vpnc ya está corriendo (app cerrada con 'sin desconectar'), retomar el monitoreo."""
        if not vpn_proceso_activo():
            return
        d = leer_sesion()
        usuario = d.get("usuario") or self.ajustes.data.get("usuario", "")
        gw = d.get("gateway") or self.ajustes.data.get("gateway") or GATEWAY_DEFAULT
        clave = Llavero.leer(usuario) if usuario else None
        self.sesion = Sesion(usuario or "desconocido", clave or "", gw)
        self.var_user.set(usuario)
        self.var_gw.set(gw)
        self.conectado_desde = d.get("desde") or time.time()
        self.estado = CONECTADO
        self._iniciar_supervisor()
        log.info("Sesión VPN existente retomada (%s)", self.sesion.usuario)

    # ------------------------------------------------------------- monitor
    def _iniciar_supervisor(self):
        self.detener = threading.Event()
        self.hilo = threading.Thread(target=self._supervisor, args=(self.detener,), daemon=True)
        self.hilo.start()

    def _supervisor(self, detener):
        fallos = 0
        log.info("Monitor iniciado")
        while not detener.wait(CHECK_INTERVAL):
            if vpn_saludable():
                fallos = 0
                continue
            fallos += 1
            log.warning("Chequeo fallido (%d/%d)", fallos, FAIL_THRESHOLD)
            # Proceso y túnel vivos: solo falló el ping -> esperar al umbral.
            # Proceso muerto o túnel ausente: caída segura -> actuar ya.
            if vpn_proceso_activo() and tunel_existe() and fallos < FAIL_THRESHOLD:
                continue
            if not self._recuperar(detener):
                return
            fallos = 0

    def _recuperar(self, detener):
        self.eventos.put(("caida", time.strftime("%H:%M")))
        log.warning("CAÍDA DETECTADA")
        desconectar_vpn()                    # limpia restos (rutas, interfaz, proceso colgado)
        for intento in range(1, MAX_RETRIES + 1):
            espera = 5 * intento
            self.eventos.put(("reintento", intento, MAX_RETRIES, espera))
            if detener.wait(espera):
                return False
            s = self.sesion
            if not s or not s.clave:
                self.eventos.put(("necesita_clave",))
                return False
            ok, salida = conectar_vpn(s)
            if detener.is_set():             # el usuario canceló mientras se conectaba
                if ok:
                    desconectar_vpn()
                return False
            if ok:
                self.eventos.put(("reconectado",))
                log.info("Reconectado en el intento %d", intento)
                return True
            log.warning("Reintento %d falló: %s", intento, salida)
            if es_error_auth(salida):        # NO insistir: podría bloquear la cuenta corporativa
                self.eventos.put(("auth_rechazada",))
                return False
        self.eventos.put(("rendido",))
        return False

    # -------------------------------------------------------------- eventos
    def _procesar_eventos(self):
        while True:
            try:
                ev = self.eventos.get_nowait()
            except queue.Empty:
                break
            try:
                self._manejar(ev)
            except Exception:
                log.exception("Error manejando evento %s", ev)
        self.root.after(200, self._procesar_eventos)

    def _manejar(self, ev):
        tipo, args = ev[0], ev[1:]
        activo = self.estado in (CONECTADO, RECONECTANDO)

        if tipo == "conexion_ok" and self.estado == CONECTANDO:
            self.estado = CONECTADO
            self.conectado_desde = time.time()
            self.reconexiones = 0
            self._guardar_preferencias(self.sesion)
            guardar_sesion(self.sesion, self.conectado_desde)
            self._iniciar_supervisor()
            self._aplicar_estado()

        elif tipo == "conexion_error" and self.estado == CONECTANDO:
            salida = args[0]
            log.warning("Fallo de conexión: %s", salida)
            self.estado = DESCONECTADO
            self._aplicar_estado()
            if es_error_auth(salida):
                self._mostrar_error("Usuario o contraseña rechazados.\nVerifique sus datos o actualice "
                                    "la contraseña.")
            else:
                detalle = salida.splitlines()[-1] if salida else ""
                self._mostrar_error("No se pudo establecer la conexión.\nVerifique su internet y "
                                    "credenciales." + (f"\nDetalle: {detalle}" if detalle else ""))

        elif tipo == "caida" and activo:
            self.hora_caida = args[0]
            self.estado = RECONECTANDO
            self.caida_desde = time.time()
            self.lbl_aviso.config(fg=WARN, text=f"Se perdió la conexión a las {self.hora_caida}.\n"
                                                "Preparando reintento…")
            self._aplicar_estado()
            notificar("VPN VIVA caída", "Se perdió la conexión. Reintentando…", urgente=True)
            self._traer_al_frente()

        elif tipo == "reintento" and self.estado == RECONECTANDO:
            n, total, espera = args
            self.lbl_aviso.config(text=f"Se perdió la conexión a las {self.hora_caida}.\n"
                                       f"Reintento {n} de {total} en {espera} s…")

        elif tipo == "reconectado" and self.estado == RECONECTANDO:
            self.estado = CONECTADO
            self.conectado_desde = time.time()
            self.reconexiones += 1
            guardar_sesion(self.sesion, self.conectado_desde)
            self._aplicar_estado()
            notificar("VPN VIVA restablecida", "La conexión se recuperó.")

        elif tipo in ("auth_rechazada", "necesita_clave", "rendido") and self.estado == RECONECTANDO:
            self.estado = DESCONECTADO
            borrar_sesion()
            self._aplicar_estado()
            self._traer_al_frente()
            if tipo == "auth_rechazada":
                notificar("VPN VIVA desconectada", "La contraseña fue rechazada.", urgente=True)
                self._mostrar_error("La contraseña fue rechazada al reconectar.\nActualícela para continuar.")
                self.root.after(300, lambda: self._dialogo_clave(reconectar_tras=True))
            elif tipo == "necesita_clave":
                notificar("VPN VIVA desconectada", "Ingrese su contraseña para reconectar.", urgente=True)
                self._mostrar_error("Se perdió la conexión y no hay contraseña guardada.\n"
                                    "Ingrésela para reconectar.")
                self.e_pass.focus_set()
            else:
                notificar("VPN VIVA desconectada", f"No se pudo reconectar tras {MAX_RETRIES} intentos.",
                          urgente=True)
                self._mostrar_error(f"No se pudo reconectar tras {MAX_RETRIES} intentos.\n"
                                    "Revise su conexión e intente de nuevo.")

        elif tipo == "desconectado":
            self.estado = DESCONECTADO
            self._aplicar_estado()
            if self.reconectar_despues:
                self.reconectar_despues = False
                self.root.after(100, self._click_conectar)


# ==============================================================================
# ARRANQUE
# ==============================================================================
def adquirir_lock():
    """Impide abrir dos instancias (dos monitores peleándose por la misma VPN)."""
    os.makedirs(STATE_DIR, exist_ok=True)
    fd = open(LOCK_PATH, "w")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return None
    return fd


def main():
    configurar_log()
    root = tk.Tk()
    lock = adquirir_lock()
    if lock is None:
        root.withdraw()
        messagebox.showinfo(APP_NAME, "VPN VIVA ya está abierta.\nRevise la barra de tareas.")
        return 1
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
