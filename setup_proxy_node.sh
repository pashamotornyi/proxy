#!/bin/bash

# Пример запуска:
# ./setup_proxy_node.sh <FORWARD_IP> <PASSWORD> [--disable-ufw] [--final] [--add-hosts]

FORWARD_IP="$1"
PASSWORD="$2"
DISABLE_UFW=false
IS_FINAL=false
ADD_HOSTS=false

# Обработка флагов
for arg in "$@"; do
  [[ "$arg" == "--disable-ufw" ]] && DISABLE_UFW=true
  [[ "$arg" == "--final" ]] && IS_FINAL=true
  [[ "$arg" == "--add-hosts" ]] && ADD_HOSTS=true
done

# Проверка
if [[ -z "$FORWARD_IP" || -z "$PASSWORD" ]]; then
  echo "Использование: $0 <FORWARD_IP> <PASSWORD> [--disable-ufw] [--final] [--add-hosts]"
  exit 1
fi

echo "[1/7] Обновление системы..."
sudo apt update && sudo apt upgrade -y

echo "[2/7] Установка Docker и Compose..."
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release docker-compose

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io

sudo usermod -aG docker "$USER"

if $DISABLE_UFW; then
  echo "[3/7] Отключение ufw..."
  sudo ufw disable
fi

if ! $IS_FINAL; then
  echo "[4/7] Создание docker-compose.yml для Glider..."
  cat <<EOF > docker-compose.yml
version: '3.0'
services:
  api:
    image: nadoo/glider
    container_name: proxy
    ports:
      - "1080:1080"
      - "8388:8388"
    restart: unless-stopped
    logging:
      driver: 'json-file'
      options:
        max-size: '800k'
        max-file: '10'
    command: -verbose -listen ss://AEAD_AES_256_GCM:${PASSWORD}@api:8388 -forward ss://AEAD_AES_256_GCM:${PASSWORD}@${FORWARD_IP}:8388
EOF

  echo "[5/7] Запуск контейнера..."
  docker-compose up -d
fi

if $IS_FINAL; then
  echo "[6/7] Настройка конечного сервера Shadowsocks..."

  sudo apt install -y snapd
  sudo snap install shadowsocks-libev

  CONFIG_PATH="/var/snap/shadowsocks-libev/common/etc/shadowsocks-libev"
  sudo mkdir -p "$CONFIG_PATH"

  cat <<EOF | sudo tee "$CONFIG_PATH/config.json" > /dev/null
{
  "server":["::0", "0.0.0.0"],
  "mode":"tcp_and_udp",
  "server_port":8388,
  "local_port":1080,
  "password":"$PASSWORD",
  "timeout":60,
  "fast_open":true,
  "reuse_port": true,
  "no_delay": true,
  "method":"aes-256-gcm"
}
EOF

  echo "[Unit]
Description=Shadowsocks-Libev Custom Server Service for %I
Documentation=man:ss-server(1)
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/snap run shadowsocks-libev.ss-server -c $CONFIG_PATH/%i.json

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/shadowsocks-libev-server@.service > /dev/null

  sudo systemctl enable --now shadowsocks-libev-server@config
  sudo iptables -I INPUT -p tcp --dport 8388 -j ACCEPT
  sudo iptables -I INPUT -p udp --dport 8388 -j ACCEPT

  if $ADD_HOSTS; then
    echo "[7/7] Обновление /etc/hosts для fapi.binance.com..."

    BINANCE_IPS=(
      "13.225.164.218" "13.227.61.59" "143.204.127.42" "13.35.51.41"
      "99.84.58.138" "18.65.193.131" "18.65.176.132" "99.84.140.147"
      "13.225.173.96" "54.240.188.143" "13.35.55.41" "18.65.207.131"
      "143.204.79.125" "65.9.40.137" "99.84.137.147" "18.65.212.131"
    )

    declare -A results

    for ip in "${BINANCE_IPS[@]}"; do
      ping_time=$(ping -c 1 -W 1 "$ip" | grep 'time=' | awk -F'time=' '{print $2}' | awk '{print $1}')
      results[$ip]=$ping_time
    done

    best_ip=$(for ip in "${!results[@]}"; do
      echo "$ip ${results[$ip]}"
    done | sort -k2 -n | head -n1 | awk '{print $1}')

    echo "$best_ip fapi.binance.com" | sudo tee -a /etc/hosts > /dev/null
  fi
fi

echo "✅ Готово. Перезагрузите сервер командой: sudo reboot"
