#!/usr/bin/env bash
set -Eeuo pipefail

# Назначение:
# Настройка узла цепочки прокси.
# - Промежуточный узел (по умолчанию): Glider в Docker, форвард на конечный Shadowsocks.
# - Конечный узел (--final): Shadowsocks-libev (snap) как конечная точка.

STATE_FILE="/root/.setup_state"
SERVICE_NAME="proxy_setup_continue"
SCRIPT_PATH="$(realpath "$0")"
LOG_FILE="/var/log/proxy-setup.log"   # единый лог «болтливых» команд

# Вывод шагов
step() { printf "\n=== %s ===\n" "$*"; }
ok()  { printf "Ок\n"; }
die() { printf "Ошибка: %s\n" "$*" >&2; exit 1; }
require_root() { [[ $EUID -eq 0 ]] || die "Запускать от root"; }

# Сохранить состояние
save_state() {
  install -d -m 700 "$(dirname "$STATE_FILE")"
  install -d -m 755 "$(dirname "$LOG_FILE")" 2>/dev/null || true
  touch "$LOG_FILE" || true
  cat > "$STATE_FILE" <<EOF
FORWARD_IP=${FORWARD_IP:-}
PASSWORD=${PASSWORD:-}
IS_FINAL=${IS_FINAL:-false}
START_STEP=${1:-1}
EOF
}

# systemd-юнит для возобновления
create_resume_service() {
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Resume proxy setup after reboot
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/bash -lc '${SCRIPT_PATH} --resume'
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload >>"$LOG_FILE" 2>&1
  systemctl enable --quiet "${SERVICE_NAME}" >>"$LOG_FILE" 2>&1
}

disable_resume_service() {
  systemctl disable --quiet "${SERVICE_NAME}" >>"$LOG_FILE" 2>&1 || true
  rm -f "/etc/systemd/system/${SERVICE_NAME}.service" || true
  systemctl daemon-reload >>"$LOG_FILE" 2>&1
}

# Безопасные apt-хелперы (ожидание локов + мягкая остановка u-u при необходимости)
apt_safe_update_upgrade() {
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 update >>"$LOG_FILE" 2>&1
  if ! DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
       apt-get -o DPkg::Lock::Timeout=600 -y -o Dpkg::Options::="--force-confnew" upgrade >>"$LOG_FILE" 2>&1; then
    systemctl stop unattended-upgrades >>"$LOG_FILE" 2>&1 || true
    for i in $(seq 1 60); do
      if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then break; fi
      sleep 5
    done
    DEBIAN_FRONTEND=noninteractive apt-get -y update >>"$LOG_FILE" 2>&1
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
      apt-get -y -o Dpkg::Options::="--force-confnew" upgrade >>"$LOG_FILE" 2>&1
    systemctl start unattended-upgrades >>"$LOG_FILE" 2>&1 || true
  fi
}

apt_safe_install() {
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 update >>"$LOG_FILE" 2>&1 || true
  if ! DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=600 -y install "$@" >>"$LOG_FILE" 2>&1; then
    systemctl stop unattended-upgrades >>"$LOG_FILE" 2>&1 || true
    for i in $(seq 1 60); do
      if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then break; fi
      sleep 5
    done
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -y install "$@" >>"$LOG_FILE" 2>&1
    systemctl start unattended-upgrades >>"$LOG_FILE" 2>&1 || true
  fi
}

# Аргументы
FORWARD_IP=""; PASSWORD=""; IS_FINAL=false; RESUME=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --forward-ip) FORWARD_IP="${2:?}"; shift 2;;
    --password)   PASSWORD="${2:?}"; shift 2;;
    --final)      IS_FINAL=true; shift;;
    --resume)     RESUME=true; shift;;
    *) die "Неизвестный аргумент: $1";;
  esac
done

require_root

# Возобновление
if [[ -f "$STATE_FILE" && "$RESUME" == true ]]; then
  step "Обнаружено состояние — продолжаем после перезагрузки"
  # shellcheck source=/dev/null
  source "$STATE_FILE"
  ok
else
  if [[ "$IS_FINAL" == true ]]; then
    [[ -n "${PASSWORD:-}" ]] || die "Для --final требуется --password"
  else
    [[ -n "${FORWARD_IP:-}" && -n "${PASSWORD:-}" ]] || die "Требуются --forward-ip и --password"
  fi
  save_state 1
  create_resume_service
fi

START_STEP="${START_STEP:-1}"

# [1/8] Обновление системы
if [[ "$START_STEP" -le 1 ]]; then
  step "[1/8] Обновление системы (авто-рестарт сервисов)"
  if [[ -f /etc/needrestart/needrestart.conf ]]; then
    sed -i "s/^\s*\$nrconf{restart}.*/\$nrconf{restart} = 'a';/; t; \$ a \$nrconf{restart} = 'a';" /etc/needrestart/needrestart.conf >>"$LOG_FILE" 2>&1 || true
    sed -i "s/^\s*\$nrconf{kernelhints}.*/\$nrconf{kernelhints} = 0;/" /etc/needrestart/needrestart.conf >>"$LOG_FILE" 2>&1 || true
  fi
  retry=3
  until apt_safe_update_upgrade; do
    ((retry--)); ((retry==0)) && die "apt upgrade не удалось"
    sleep 3
  done
  ok
  save_state 2
fi

# [2/8] Базовые инструменты
if [[ "$START_STEP" -le 2 ]]; then
  step "[2/8] Установка базовых инструментов"
  apt_safe_install ca-certificates curl gnupg lsb-release jq net-tools dnsutils iproute2 python3-pip
  ok
  save_state 3
fi

# [3/8] Docker и Compose
if [[ "$START_STEP" -le 3 ]]; then
  step "[3/8] Установка Docker и Compose"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg >>"$LOG_FILE" 2>&1
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get update >>"$LOG_FILE" 2>&1
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >>"$LOG_FILE" 2>&1
  ok
  save_state 4
fi

# [4/8] Настройка фаервола
if [[ "$START_STEP" -le 4 ]]; then
  step "[4/8] Настройка фаервола (открываем порты)"
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q Status; then
    ufw allow 1080/tcp >>"$LOG_FILE" 2>&1 || true
    ufw allow 8388/tcp >>"$LOG_FILE" 2>&1 || true
    ufw allow 8388/udp >>"$LOG_FILE" 2>&1 || true
    ufw reload >>"$LOG_FILE" 2>&1 || true
  fi
  iptables -I INPUT -p tcp --dport 1080 -j ACCEPT >>"$LOG_FILE" 2>&1 || true
  iptables -I INPUT -p tcp --dport 8388 -j ACCEPT >>"$LOG_FILE" 2>&1 || true
  iptables -I INPUT -p udp --dport 8388 -j ACCEPT >>"$LOG_FILE" 2>&1 || true
  ok
  save_state 5
fi

# [5/8] Промежуточный узел (Glider в Docker)
if [[ "$IS_FINAL" == false && "$START_STEP" -le 5 ]]; then
  step "[5/8] Настройка промежуточного узла (Glider в Docker)"
  mkdir -p /opt/glider
  cat > /opt/glider/docker-compose.yml <<EOF
services:
  proxy:
    image: nadoo/glider:0.16.0
    container_name: glider-proxy
    restart: unless-stopped
    ports:
      - "1080:1080"
      - "8388:8388"
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    healthcheck:
      test: ["CMD-SHELL", "ss -lntup | grep -E '(:1080|:8388)'"]
      interval: 30s
      timeout: 5s
      retries: 10
    command: >
      -verbose
      -listen ss://AEAD_AES_256_GCM:${PASSWORD}@0.0.0.0:8388
      -forward ss://AEAD_AES_256_GCM:${PASSWORD}@${FORWARD_IP}:8388
      -dns 8.8.8.8:53
      -strategy rr
EOF
  docker compose -f /opt/glider/docker-compose.yml up -d >>"$LOG_FILE" 2>&1
  ok
  save_state 6
fi

# [6/8] Конечный узел (Shadowsocks-libev)
if [[ "$IS_FINAL" == true && "$START_STEP" -le 6 ]]; then
  step "[6/8] Настройка конечного узла (Shadowsocks-libev)"
  apt_safe_install snapd
  snap install shadowsocks-libev >>"$LOG_FILE" 2>&1
  CONFIG_PATH="/var/snap/shadowsocks-libev/common/etc/shadowsocks-libev"
  install -d -m 755 "$CONFIG_PATH"
  cat > "$CONFIG_PATH/config.json" <<EOF
{
  "server": ["::0","0.0.0.0"],
  "mode": "tcp_and_udp",
  "server_port": 8388,
  "local_port": 1080,
  "password": "${PASSWORD}",
  "timeout": 60,
  "fast_open": true,
  "reuse_port": true,
  "no_delay": true,
  "method": "aes-256-gcm"
}
EOF
  cat > /etc/systemd/system/shadowsocks-libev-server@.service <<'EOF'
[Unit]
Description=Shadowsocks-Libev Custom Server Service for %I
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
Environment=CONFIG_PATH=/var/snap/shadowsocks-libev/common/etc/shadowsocks-libev
ExecStart=/usr/bin/snap run shadowsocks-libev.ss-server -c ${CONFIG_PATH}/%i.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload >>"$LOG_FILE" 2>&1
  systemctl enable --quiet --now shadowsocks-libev-server@config >>"$LOG_FILE" 2>&1
  ok
  save_state 7
fi

# [7/8] Проверка сервисов
if [[ "$START_STEP" -le 7 ]]; then
  step "[7/8] Проверка состояния сервисов"
  if [[ "$IS_FINAL" == true ]]; then
    systemctl --no-pager status shadowsocks-libev-server@config >>"$LOG_FILE" 2>&1 || true
    ss -lntup | grep -E ':8388' >>"$LOG_FILE" 2>&1 || true
  else
    docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' >>"$LOG_FILE" 2>&1 || true
  fi
  ok
  save_state 8
fi

# [8/8] Очистка
if [[ "$START_STEP" -le 8 ]]; then
  step "[8/8] Очистка и завершение"
  rm -f "$STATE_FILE" || true
  disable_resume_service
  ok
  printf "✅ Установка завершена\n"
  printf "Логи: %s\n" "$LOG_FILE" >>"$LOG_FILE" 2>&1 || true
fi
