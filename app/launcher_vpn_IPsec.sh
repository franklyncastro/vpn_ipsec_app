#!/bin/bash
# ==============================================================================
# Instala el lanzador de VPN VIVA (menú de aplicaciones + icono en el escritorio)
# Uso: colocar este archivo junto a vpn_viva.py y ejecutar:  bash instalar_launcher.sh
# ==============================================================================
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/vpn_viva.py"
DEST="$HOME/.local/share/vpn-viva"                 # donde vivirá la app
APPS="$HOME/.local/share/applications"             # menú de aplicaciones
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"   # 'Escritorio' o 'Desktop'

[ -f "$SRC" ] || { echo "ERROR: no encuentro vpn_viva.py junto a este instalador."; exit 1; }

# Aviso (no bloquea) si faltan dependencias
python3 -c "import tkinter" 2>/dev/null || echo "AVISO: falta python3-tk -> sudo apt install -y python3-tk"
command -v secret-tool >/dev/null || echo "AVISO: falta libsecret-tools (no podrá guardar credenciales)"

mkdir -p "$DEST" "$APPS" "$DESKTOP_DIR"
install -m 755 "$SRC" "$DEST/vpn_viva.py"

# Icono (SVG): círculo blanco con punto verde
cat > "$DEST/vpn-viva.svg" <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="14" fill="#5B6D84"/>
  <circle cx="32" cy="32" r="17" fill="none" stroke="#F4F7FA" stroke-width="4"/>
  <circle cx="32" cy="32" r="8" fill="#3DDC84"/>
</svg>
EOF

# Lanzador
cat > "$APPS/vpn-viva.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=VPN VIVA
Comment=Conexión VPN corporativa con monitoreo y reconexión automática
Exec=/usr/bin/python3 $DEST/vpn_viva.py
Icon=$DEST/vpn-viva.svg
Terminal=false
Categories=Network;
EOF
chmod 755 "$APPS/vpn-viva.desktop"

# Copia en el escritorio, marcada como ejecutable y de confianza
cp "$APPS/vpn-viva.desktop" "$DESKTOP_DIR/vpn-viva.desktop"
chmod +x "$DESKTOP_DIR/vpn-viva.desktop"
command -v gio >/dev/null && gio set "$DESKTOP_DIR/vpn-viva.desktop" metadata::trusted true 2>/dev/null || true

echo "Listo."
echo "  App instalada en:  $DEST"
echo "  Menú:              busque 'VPN VIVA' en el menú de aplicaciones"
echo "  Escritorio:        $DESKTOP_DIR/vpn-viva.desktop"
