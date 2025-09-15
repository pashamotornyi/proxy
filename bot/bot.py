#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ipaddress
import discord
from discord.ext import commands
import asyncssh

# ================= Конфигурация окружения =================
TOKEN = os.environ["DISCORD_BOT_TOKEN"]            # токен бота (обязателен) [1]
SCRIPT_URL = os.environ["SCRIPT_URL"]              # RAW URL на setup_reboot.sh (обязателен) [1]
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))  # канал для кнопки [1]
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")                    # имя роли (опционально) [1]
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}  # белый список ID [1]
ALLOW_ALL = os.environ.get("ALLOW_ALL", "") == "1"  # разрешить всем (упрощённый режим) [1]

SSH_KNOWN_HOSTS = None  # при проде используйте верификацию host key (known_hosts) [3]

# ================= Discord клиент =================
intents = discord.Intents.default()  # для компонентов/slash default достаточно [1]
bot = commands.Bot(command_prefix="!", intents=intents)  # основной клиент [1]

# ================= Вспомогательные функции =================
def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v); return True
    except Exception:
        return False  # простая валидация IPv4/IPv6 [5]

def sh_esc(s: str) -> str:
    return '"' + s.replace('"', '\\"') + '"'  # безопасная цитата аргументов для bash -lc [5]

def user_allowed_ctx(interaction: discord.Interaction) -> bool:
    if ALLOW_ALL:
        return True  # принудительный допуск для отладки [1]
    if ALLOWED_USERS and interaction.user.id in ALLOWED_USERS:
        return True  # явное разрешение по ID [1]
    if interaction.guild:
        member = interaction.guild.get_member(interaction.user.id) or interaction.user
        if ALLOWED_ROLE and isinstance(member, discord.Member) and any(r.name == ALLOWED_ROLE for r in member.roles):
            return True  # проверка роли [1]
        return isinstance(member, discord.Member) and member.guild_permissions.administrator  # разрешаем администраторам [1]
    if ALLOWED_CHANNEL_ID:
        ch = interaction.client.get_channel(ALLOWED_CHANNEL_ID)
        guild = getattr(ch, "guild", None)
        if guild:
            member = guild.get_member(interaction.user.id)
            if member:
                if ALLOWED_ROLE and any(r.name == ALLOWED_ROLE for r in member.roles):
                    return True  # роль ок [1]
                return member.guild_permissions.administrator  # админ ок [1]
    return False  # deny-by-default [1]

# ================= Идемпотентная настройка локали UTF‑8 =================
LOCALE_FIX = r"""
set -Eeuo pipefail
if ! locale -a 2>/dev/null | grep -qi '^en_US\.utf8$'; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y locales >/dev/null 2>&1 || true
  sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen || echo 'en_US.UTF-8 UTF-8' >> /etc/locale.gen
  locale-gen en_US.UTF-8 >/dev/null 2>&1 || true
fi
update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 LANGUAGE=en_US:en >/dev/null 2>&1 || true
export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 LANGUAGE=en_US:en
echo "--- locale (first lines) ---"
locale | sed -n '1,8p'
"""  # генерирует en_US.UTF‑8 и включает по умолчанию, печатает первые строки locale [4][6]

# ================= UI: кнопки и модалки =================
class StartView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # без таймаута [1]

    @discord.ui.button(label="Начать настройку", style=discord.ButtonStyle.primary, custom_id="start_setup")
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not user_allowed_ctx(interaction):
            await interaction.response.send_message("Недостаточно прав для запуска мастера.", ephemeral=True)  # приватный отказ [1]
            return
        await interaction.response.defer(ephemeral=True)  # подтверждение [1]
        try:
            dm = await interaction.user.create_dm()
            await dm.send("Выберите тип сервера:", view=RoleView())  # переход в DM [1]
            await interaction.followup.send("Открыл личные сообщения.", ephemeral=True)  # уведомление [1]
        except discord.Forbidden:
            await interaction.followup.send("Не удалось написать в личные сообщения (закрыт DM).", ephemeral=True)  # DM закрыт [1]

class RoleView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)  # 10 минут [1]

    @discord.ui.button(label="Промежуточный сервер", style=discord.ButtonStyle.secondary, custom_id="intermediate")
    async def inter(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IntermediateModal(title="Промежуточный сервер"))  # модалка [1]

    @discord.ui.button(label="Финальный сервер", style=discord.ButtonStyle.success, custom_id="final")
    async def final(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(FinalModal(title="Финальный сервер"))  # модалка [1]

# Порядок полей: ssh_pass вторым и обязательным
class IntermediateModal(discord.ui.Modal, title="Промежуточный сервер"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)  # 1 [7]
    ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)  # 2 [7]
    forward_ip = discord.ui.TextInput(label="IP следующего сервера", placeholder="5.6.7.8", required=True)  # 3 [7]
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)  # 4 [7]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [1]
        if not valid_ip(str(self.forward_ip)):
            return await interaction.followup.send("Некорректный forward_ip.", ephemeral=True)  # валидация [5]
        params = dict(
            host=str(self.host),
            user="root",
            port=22,
            password=str(self.ssh_pass),
            forward_ip=str(self.forward_ip),
            ss_password=str(self.ss_password),
        )  # сбор параметров [1]
        await run_remote_setup(interaction, mode="intermediate", params=params)  # запуск [1]

class FinalModal(discord.ui.Modal, title="Финальный сервер"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)  # 1 [7]
    ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)  # 2 [7]
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)  # 3 [7]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [1]
        params = dict(
            host=str(self.host),
            user="root",
            port=22,
            password=str(self.ssh_pass),
            ss_password=str(self.ss_password),
        )  # сбор параметров [1]
        await run_remote_setup(interaction, mode="final", params=params)  # запуск [1]

# ================= Выполнение на удалённом сервере =================
async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(text: str):
        chunk = text[-1800:] if len(text) > 1800 else text  # лимит сообщения [1]
        if chunk.strip():
            await interaction.followup.send(chunk, ephemeral=True)  # DM-ответ [1]

    await send("Подключение по SSH и проверка локали (UTF‑8)…")  # старт [4]
    conn_kwargs = dict(
        host=params["host"],
        username=params["user"],
        known_hosts=SSH_KNOWN_HOSTS,
        port=params["port"],
        password=params.get("password", None),
    )  # параметры asyncssh [3]

    try:
        async with asyncssh.connect(**conn_kwargs) as conn:  # сессия SSH [3]
            # 1) Локаль
            rc1 = await run_and_stream(conn, LOCALE_FIX, send, title="Локаль")  # en_US.UTF‑8 [4]
            if rc1 != 0:
                await send(f"Локаль: завершено с кодом {rc1}, продолжаем установку.")  # информирование [4]

            # 1.1) Установка wget и сертификатов (на минимальных образах их нет)
            install_wget = (
                "export DEBIAN_FRONTEND=noninteractive; "
                "apt-get update -y >/dev/null 2>&1 || true; "
                "apt-get install -y wget ca-certificates >/dev/null 2>&1 || true"
            )  # подготовка загрузчика [2]
            await run_and_stream(conn, install_wget, send, title="Подготовка загрузчика (wget)")  # идемпотентно [2]

            # 2) Загрузка и подготовка скрипта через wget
            fetch_cmd = f'wget -qO- "{SCRIPT_URL}" | sed \'s/\\r$//\' > setup_reboot.sh && chmod +x setup_reboot.sh'  # wget+sed [2]
            rc2 = await run_and_stream(conn, fetch_cmd, send, title="Загрузка скрипта")  # получение RAW [2]
            if rc2 != 0:
                await send(f"Ошибка загрузки скрипта, код {rc2}.")  # останов [2]
                return

            # 3) Запуск установки
            if mode == "final":
                run_cmd = f'./setup_reboot.sh --final --password {sh_esc(params["ss_password"])}'  # финальный [1]
            else:
                run_cmd = f'./setup_reboot.sh --forward-ip {sh_esc(params["forward_ip"])} --password {sh_esc(params["ss_password"])}'  # промежуточный [1]
            await send("Запускаю установку, это может занять 5–10 минут…")  # предупреждение [1]
            rc3 = await run_and_stream(conn, run_cmd, send, title="Установка", use_bash=True)  # выполнение [8]
            await send(f"Готово. Код возврата: {rc3}")  # итог [8]
    except Exception as e:
        await send(f"Ошибка SSH/выполнения: {e}")  # репорт исключения [3]

async def run_and_stream(conn: asyncssh.SSHClientConnection, cmd: str, send, title: str = "", use_bash: bool = False) -> int:
    exec_cmd = cmd if not use_bash else f'/bin/bash -lc {sh_esc(cmd)}'  # bash -lc для пайплайнов [3]
    if title:
        await send(f"— {title} —")  # секция [1]
    async with conn.create_process(exec_cmd) as proc:  # процесс на удалённой стороне [3]
        buf = []
        async for line in proc.stdout:
            buf.append(line)
            if "=== [" in line or "Ок" in line or "Ошибка" in line or len(buf) >= 10:
                await send("".join(buf))  # порционно [8]
                buf.clear()
        if buf:
            await send("".join(buf))  # остаток [8]
        rc = await proc.wait()  # код возврата [3]
        return rc

# ================= Инициализация и публикация кнопки =================
@bot.event
async def on_ready():
    try:
        await bot.tree.sync()  # синхронизация app-команд (на будущее) [1]
    except Exception as e:
        print("Slash sync error:", e)  # лог ошибки [1]
    print(f"Logged in as {bot.user}")  # подтверждение [1]
    if ALLOWED_CHANNEL_ID:
        ch = bot.get_channel(ALLOWED_CHANNEL_ID)
        if ch:
            try:
                await ch.send(
                    "Нажмите кнопку, чтобы начать приватный мастер настройки прокси.",
                    view=StartView()
                )  # публикация кнопки [1]
            except Exception as e:
                print("Failed to send start message:", e)  # лог публикации [1]

bot.run(TOKEN)  # запуск клиента [1]
