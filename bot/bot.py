#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import asyncio
import ipaddress
import discord
from discord.ext import commands
import asyncssh

# ============ Конфигурация через переменные окружения ============
TOKEN = os.environ["DISCORD_BOT_TOKEN"]           # токен бота
SCRIPT_URL = os.environ["SCRIPT_URL"]             # raw URL на setup_reboot.sh
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))  # канал с кнопкой "Начать настройку"
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")                    # имя роли, если нужно ограничить старт
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}  # белый список ID

# По SSH допустим и пароль, и ключ агента (ssh-agent) — known_hosts отключен для простоты демо (в проде задать доверенные ключи)
SSH_KNOWN_HOSTS = None

# ================== Discord и интенты ==================
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

# ================== Утилиты ==================
def user_allowed(member: discord.abc.User | discord.Member) -> bool:
    if ALLOWED_USERS and getattr(member, "id", None) in ALLOWED_USERS:
        return True
    if isinstance(member, discord.Member) and ALLOWED_ROLE:
        if any(r.name == ALLOWED_ROLE for r in member.roles):
            return True
    # по умолчанию — администраторы сервера
    return isinstance(member, discord.Member) and member.guild_permissions.administrator

def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except Exception:
        return False

def sh_esc(s: str) -> str:
    # Безопасное экранирование для аргументов командной строки
    return '"' + s.replace('"', '\\"') + '"'

# ================== Шаг фикса локали (UTF-8) ==================
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
"""

# ================== Представления (кнопки/модальные окна) ==================
class StartView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Начать настройку", style=discord.ButtonStyle.primary, custom_id="start_setup")
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Проверка прав только при нажатии кнопки
        member = interaction.user if interaction.guild is None else interaction.guild.get_member(interaction.user.id)
        if interaction.guild and not user_allowed(member):
            await interaction.response.send_message("Недостаточно прав для запуска мастера.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        try:
            dm = await interaction.user.create_dm()
            await dm.send("Выберите тип сервера:", view=RoleView())
            await interaction.followup.send("Открыл личные сообщения.", ephemeral=True)
        except discord.Forbidden:
            await interaction.followup.send("Не удалось написать в личные сообщения (закрыт DM).", ephemeral=True)

class RoleView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)

    @discord.ui.button(label="Промежуточный сервер", style=discord.ButtonStyle.secondary, custom_id="intermediate")
    async def inter(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IntermediateModal(title="Настройка промежуточного сервера"))

    @discord.ui.button(label="Финальный сервер", style=discord.ButtonStyle.success, custom_id="final")
    async def final(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(FinalModal(title="Настройка финального сервера"))

class IntermediateModal(discord.ui.Modal, title="Промежуточный"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)
    ssh_user = discord.ui.TextInput(label="SSH пользователь", placeholder="root", default="root", required=True)
    ssh_port = discord.ui.TextInput(label="SSH порт", placeholder="22", default="22", required=True)
    ssh_pass = discord.ui.TextInput(label="SSH пароль (оставьте пусто при ключе)", required=False, style=discord.TextStyle.short)
    forward_ip = discord.ui.TextInput(label="IP следующего сервера", placeholder="5.6.7.8", required=True)
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        if not valid_ip(str(self.forward_ip)):
            await interaction.followup.send("Некорректный forward_ip.", ephemeral=True)
            return
        params = dict(
            host=str(self.host),
            user=str(self.ssh_user),
            port=int(str(self.ssh_port) or "22"),
            password=(str(self.ssh_pass) or None),
            forward_ip=str(self.forward_ip),
            ss_password=str(self.ss_password),
        )
        await run_remote_setup(interaction, mode="intermediate", params=params)

class FinalModal(discord.ui.Modal, title="Финальный"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)
    ssh_user = discord.ui.TextInput(label="SSH пользователь", placeholder="root", default="root", required=True)
    ssh_port = discord.ui.TextInput(label="SSH порт", placeholder="22", default="22", required=True)
    ssh_pass = discord.ui.TextInput(label="SSH пароль (оставьте пусто при ключе)", required=False)
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        params = dict(
            host=str(self.host),
            user=str(self.ssh_user),
            port=int(str(self.ssh_port) or "22"),
            password=(str(self.ssh_pass) or None),
            ss_password=str(self.ss_password),
        )
        await run_remote_setup(interaction, mode="final", params=params)

# ================== Исполнение на удалённом сервере ==================
async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(text: str):
        # Отправка частями, чтобы не упереться в лимиты
        chunk = text[-1800:] if len(text) > 1800 else text
        if chunk.strip():
            await interaction.followup.send(chunk, ephemeral=True)

    await send("Подключение по SSH и проверка локали (UTF‑8)…")
    conn_kwargs = dict(
        host=params["host"],
        username=params["user"],
        known_hosts=SSH_KNOWN_HOSTS,
        port=params["port"],
    )
    if params.get("password"):
        conn_kwargs["password"] = params["password"]

    try:
        async with asyncssh.connect(**conn_kwargs) as conn:
            # 1) Фикс локали
            rc1 = await run_and_stream(conn, LOCALE_FIX, send, title="Локаль")
            if rc1 != 0:
                await send(f"Локаль: завершено с кодом {rc1}, продолжаем установку.")

            # 2) Скачивание и «очистка» скрипта
            fetch_cmd = f'curl -fsSL "{SCRIPT_URL}" | sed \'s/\\r$//\' > setup_reboot.sh && chmod +x setup_reboot.sh'
            rc2 = await run_and_stream(conn, fetch_cmd, send, title="Загрузка скрипта")
            if rc2 != 0:
                await send(f"Ошибка загрузки скрипта, код {rc2}.")
                return

            # 3) Формирование команды запуска
            if mode == "final":
                run_cmd = f'./setup_reboot.sh --final --password {sh_esc(params["ss_password"])}'
            else:
                run_cmd = f'./setup_reboot.sh --forward-ip {sh_esc(params["forward_ip"])} --password {sh_esc(params["ss_password"])}'

            await send("Запускаю установку, это может занять 5–10 минут…")
            rc3 = await run_and_stream(conn, run_cmd, send, title="Установка", use_bash=True)
            await send(f"Готово. Код возврата: {rc3}")
    except Exception as e:
        await send(f"Ошибка SSH/выполнения: {e}")

async def run_and_stream(conn: asyncssh.SSHClientConnection, cmd: str, send, title: str = "", use_bash: bool = False) -> int:
    # Для сложных пайплайнов можно принудительно запускать под /bin/bash -lc
    exec_cmd = cmd if not use_bash else f'/bin/bash -lc {sh_esc(cmd)}'
    header = f"— {title} —" if title else ""
    if header:
        await send(header)
    async with conn.create_process(exec_cmd) as proc:
        buf = []
        async for line in proc.stdout:
            buf.append(line)
            # пробрасываем важные маркеры шагов/статуса
            if "=== [" in line or "Ок" in line or "Ошибка" in line or len(buf) >= 10:
                await send("".join(buf))
                buf.clear()
        if buf:
            await send("".join(buf))
        rc = await proc.wait()
        return rc

# ================== Инициализация/закрепление кнопки ==================
@bot.event
async def on_ready():
    try:
        await bot.tree.sync()
    except Exception as e:
        print("Slash sync error:", e)
    print(f"Logged in as {bot.user}")

    if ALLOWED_CHANNEL_ID:
        ch = bot.get_channel(ALLOWED_CHANNEL_ID)
        if ch:
            try:
                await ch.send(
                    "Нажмите кнопку, чтобы начать приватный мастер настройки прокси.",
                    view=StartView()
                )
            except Exception:
                pass

bot.run(TOKEN)
