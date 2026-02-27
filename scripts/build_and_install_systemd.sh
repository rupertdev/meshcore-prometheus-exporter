#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

APP_NAME="meshcore-prom-exporter"
DIST_BIN="${ROOT_DIR}/dist/${APP_NAME}"
MESHCLI_NAME="meshcli"
DIST_MESHCLI_BIN="${ROOT_DIR}/dist/${MESHCLI_NAME}"
SERVICE_SRC="${ROOT_DIR}/deploy/systemd/${APP_NAME}.service"
ENV_SRC="${ROOT_DIR}/deploy/systemd/${APP_NAME}.env.example"

INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/meshcore-prom-exporter}"
INSTALL_BIN="${INSTALL_PREFIX}/${APP_NAME}"
INSTALL_MESHCLI_BIN="${INSTALL_PREFIX}/${MESHCLI_NAME}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
CONFIG_DIR="${CONFIG_DIR:-/etc/meshcore-prom-exporter}"
CONFIG_FILE="${CONFIG_DIR}/${APP_NAME}.env"
WORK_DIR="${WORK_DIR:-/var/lib/meshcore-prom-exporter}"
SUDO_BIN="${SUDO_BIN:-sudo}"

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "pyinstaller not found. Install dev dependencies first: pip install -e \".[dev]\"" >&2
  exit 1
fi

if ! python -c "import meshcore_cli.meshcore_cli" >/dev/null 2>&1; then
  echo "meshcore-cli python package not found in current environment." >&2
  echo "Install it with: python -m pip install meshcore-cli" >&2
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

echo "Building ${MESHCLI_NAME} executable with PyInstaller..."
MESHCLI_ENTRY="$(python -c 'import meshcore_cli.meshcore_cli as m; print(m.__file__)')"
pyinstaller --clean --onefile --name "${MESHCLI_NAME}" "${MESHCLI_ENTRY}"

if [[ ! -f "${DIST_MESHCLI_BIN}" ]]; then
  echo "Build failed: ${DIST_MESHCLI_BIN} not found" >&2
  exit 1
fi

echo "Installing executable to ${INSTALL_BIN}..."
"${SUDO_BIN}" install -d "${INSTALL_PREFIX}"
"${SUDO_BIN}" install -m 0755 "${DIST_BIN}" "${INSTALL_BIN}"
"${SUDO_BIN}" install -m 0755 "${DIST_MESHCLI_BIN}" "${INSTALL_MESHCLI_BIN}"

echo "Ensuring working directory exists at ${WORK_DIR}..."
"${SUDO_BIN}" install -d "${WORK_DIR}"

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
