#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

APP_NAME="meshcore-prom-exporter"
DIST_BIN="${ROOT_DIR}/dist/${APP_NAME}"
SERVICE_SRC="${ROOT_DIR}/deploy/systemd/${APP_NAME}.service"
ENV_SRC="${ROOT_DIR}/deploy/systemd/${APP_NAME}.env.example"

INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/meshcore-prom-exporter}"
INSTALL_BIN="${INSTALL_PREFIX}/${APP_NAME}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
CONFIG_DIR="${CONFIG_DIR:-/etc/meshcore-prom-exporter}"
CONFIG_FILE="${CONFIG_DIR}/${APP_NAME}.env"
SUDO_BIN="${SUDO_BIN:-sudo}"

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "pyinstaller not found. Install dev dependencies first: pip install -e \".[dev]\"" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found on this host. This script requires a systemd-based system." >&2
  exit 1
fi

echo "Building ${APP_NAME} executable with PyInstaller..."
pyinstaller --clean --onefile --name "${APP_NAME}" --paths "${ROOT_DIR}/src" "${ROOT_DIR}/src/meshcore_prom_exporter/__main__.py"

if [[ ! -f "${DIST_BIN}" ]]; then
  echo "Build failed: ${DIST_BIN} not found" >&2
  exit 1
fi

echo "Installing executable to ${INSTALL_BIN}..."
"${SUDO_BIN}" install -d "${INSTALL_PREFIX}"
"${SUDO_BIN}" install -m 0755 "${DIST_BIN}" "${INSTALL_BIN}"

echo "Installing systemd unit to ${SYSTEMD_DIR}/${APP_NAME}.service..."
"${SUDO_BIN}" install -d "${SYSTEMD_DIR}"
"${SUDO_BIN}" install -m 0644 "${SERVICE_SRC}" "${SYSTEMD_DIR}/${APP_NAME}.service"

echo "Installing config template to ${CONFIG_FILE} if missing..."
"${SUDO_BIN}" install -d "${CONFIG_DIR}"
if "${SUDO_BIN}" test -f "${CONFIG_FILE}"; then
  echo "Config already exists at ${CONFIG_FILE}; leaving it unchanged."
else
  "${SUDO_BIN}" install -m 0644 "${ENV_SRC}" "${CONFIG_FILE}"
fi

echo "Reloading systemd daemon..."
"${SUDO_BIN}" systemctl daemon-reload

cat <<EOF
Done.
Next steps:
  ${SUDO_BIN} systemctl enable --now ${APP_NAME}
  ${SUDO_BIN} systemctl status ${APP_NAME}
EOF
