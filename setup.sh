#!/bin/bash

set -e

# Флаги
ADD_HOSTS=false
FINAL_NODE=false

# Парсинг флагов
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --add-hosts) ADD_HOSTS=true ;;
        --final-node) FINAL_NODE=true ;;
    esac
    shift
done

# Список IP-адресов
ip_list=$(dig +short fapi.binance.com | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')

# Функция проверки IP и измерения времени
check_ip() {
    local ip=$1
    local result=$(curl -m 3 -s -w "%{time_total}" -o /dev/null --resolve fapi.binance.com:443:$ip https://fapi.binance.com)
    if [[ -n "$result" ]]; then
        echo "$ip $result"
    fi
}

# Найти IP с наименьшим временем
best_ip=""
best_time=100000

echo "[*] Проверка IP..."
while read -r ip; do
    result=$(check_ip "$ip")
    if [[ -n "$result" ]]; then
        ip_addr=$(echo "$result" | awk '{print $1}')
        ip_time=$(echo "$result" | awk '{print $2}')
        echo "    $ip_addr: $ip_time"
        if (( $(echo "$ip_time < $best_time" | bc -l) )); then
            best_ip=$ip_addr
            best_time=$ip_time
        fi
    else
        echo "    $ip: ❌ недоступен"
    fi
done <<< "$ip_list"

if [[ -z "$best_ip" ]]; then
    echo "[!] Не удалось определить доступный IP."
    exit 1
fi

echo "[+] Лучший IP: $best_ip ($best_time сек)"

if $ADD_HOSTS; then
    echo "[*] Обновление /etc/hosts"
    sudo sed -i '/fapi\.binance\.com/d' /etc/hosts
    echo "$best_ip fapi.binance.com" | sudo tee -a /etc/hosts > /dev/null
fi

# Если указано, что это последний сервер в цепочке
if $FINAL_NODE; then
    echo "[*] Последний сервер в цепочке — настройка завершена."
    # Можно добавить логику финальной настройки
fi
