#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ipaddress
import discord
from discord.ext import commands
import asyncssh
import aiohttp  # requirements: aiohttp>=3.9

# ================= Конфигурация окружения =================
TOKEN = os.environ["DISCORD_BOT_TOKEN"]            # токен бота 
SCRIPT_URL = os.environ["SCRIPT_URL"]              # RAW URL на setup_reboot.sh 
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))  # канал для кнопки 
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")                    # имя роли (опц.) 
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}  # белый список ID 
ALLOW_ALL = os.environ.get("ALLOW_ALL", "") == "1"  # разрешить всем (отладка) 
QUIET = os.environ.get("QUIET", "") == "1"          # тихий режим статусов 

SSH_KNOWN_HOSTS = None  # для продакшена настройте known_hosts/проверку host key [1]

# ================= Discord клиент =================
intents = discord.Intents.default()  # для UI достаточно default 
bot = commands.Bot(command_prefix="!", intents=intents)  # основной клиент 

# ================= Вспомогательные функции =================
def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v); return True
    except Exception:
        return False  # простая валидация IPv4/IPv6 

def sh_esc(s: str) -> str:
    return '"' + s.replace('"', '\\"') + '"'  # безопасная цитата для bash -lc 

def user_allowed_ctx(interaction: discord.Interaction) -> bool:
    if ALLOW_ALL:
        return True  # принудительный допуск 
    if ALLOWED_USERS and interaction.user.id in ALLOWED_USERS:
        return True  # белый список 
    if interaction.guild:
        member = interaction.guild.get_member(interaction.user.id) or interaction.user
        if ALLOWED_ROLE and isinstance(member, discord.Member) and any(r.name == ALLOWED_ROLE for r in member.roles):
            return True  # роль 
        return isinstance(member, discord.Member) and member.guild_permissions.administrator  # админ 
    if ALLOWED_CHANNEL_ID:
        ch = interaction.client.get_channel(ALLOWED_CHANNEL_ID)
        guild = getattr(ch, "guild", None)
        if guild:
            member = guild.get_member(interaction.user.id)
            if member:
                if ALLOWED_ROLE and any(r.name == ALLOWED_ROLE for r in member.roles):
                    return True  # роль 
                return member.guild_permissions.administrator  # админ 
    return False  # запрет 

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
"""  # включает en_US.UTF‑8; при QUIET=0 можно видеть первые строки locale 

# ================= UI: кнопки и модалки =================
class StartView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # без таймаута 

    @discord.ui.button(label="Начать настройку", style=discord.ButtonStyle.primary, custom_id="start_setup")
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not user_allowed_ctx(interaction):
            await interaction.response.send_message("Недостаточно прав для запуска мастера.", ephemeral=True)  # приватный отказ 
            return
        await interaction.response.defer(ephemeral=True)  # подтверждение [2]
        try:
            dm = await interaction.user.create_dm()
            await dm.send("Выберите тип сервера:", view=RoleView())  # переход в DM 
            await interaction.followup.send("Открыл личные сообщения.", ephemeral=True)  # уведомление [2]
        except discord.Forbidden:
            await interaction.followup.send("Не удалось написать в личные сообщения (закрыт DM).", ephemeral=True)  # DM закрыт [2]

class RoleView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)  # 10 минут 

    @discord.ui.button(label="Промежуточный сервер", style=discord.ButtonStyle.secondary, custom_id="intermediate")
    async def inter(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IntermediateModal(title="Промежуточный сервер"))  # модалка 

    @discord.ui.button(label="Финальный сервер", style=discord.ButtonStyle.success, custom_id="final")
    async def final(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(FinalModal(title="Финальный сервер"))  # модалка 

# Порядок полей: ssh_pass вторым и обязательным
class IntermediateModal(discord.ui.Modal, title="Промежуточный сервер"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)  # 1 [2]
    ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)  # 2 [2]
    forward_ip = discord.ui.TextInput(label="IP следующего сервера", placeholder="5.6.7.8", required=True)  # 3 [2]
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)  # 4 [2]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [2]
        if not valid_ip(str(self.forward_ip)):
            return await interaction.followup.send("Некорректный forward_ip.", ephemeral=True)  # проверка 
        params = dict(
            host=str(self.host),
            user="root",
            port=22,
            password=str(self.ssh_pass),
            forward_ip=str(self.forward_ip),
            ss_password=str(self.ss_password),
        )  # сбор параметров 
        await run_remote_setup(interaction, mode="intermediate", params=params)  # запуск 

class FinalModal(discord.ui.Modal, title="Финальный сервер"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)  # 1 [2]
    ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)  # 2 [2]
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)  # 3 [2]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [2]
        params = dict(
            host=str(self.host),
            user="root",
            port=22,
            password=str(self.ssh_pass),
            ss_password=str(self.ss_password),
        )  # сбор параметров 
        await run_remote_setup(interaction, mode="final", params=params)  # запуск 

# ================= Загрузка и передача файла по SFTP =================
async def download_script(url: str) -> bytes:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, allow_redirects=True) as resp:
            data = await resp.read()
            if resp.status != 200 or not data:
                raise RuntimeError(f"Download failed: HTTP {resp.status}")  # сигнализируем ошибку [3]
    text = data.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    if not text.startswith("#!"):
        raise RuntimeError("Downloaded content is not a script (no shebang)")  # защита от HTML/404 [3]
    return text.encode("utf-8")  # нормализованный UTF‑8 [3]

async def sftp_upload(conn: asyncssh.SSHClientConnection, data: bytes, remote_path: str) -> None:
    async with conn.start_sftp_client() as sftp:
        async with sftp.open(remote_path, "wb") as f:
            await f.write(data)  # бинарная запись bytes [1]
    await conn.run(f"chmod +x {sh_esc(remote_path)}", check=True)  # делаем исполняемым [1]

# ================= Исполнители шагов (успех по коду возврата) =================
async def run_silent(conn: asyncssh.SSHClientConnection, cmd: str, use_bash: bool = False):
    exec_cmd = cmd if not use_bash else f'/bin/bash -lc {sh_esc(cmd)}'  # единый вход [1]
    result = await conn.run(exec_cmd, check=False)  # не бросаем исключение [1]
    return result.exit_status, (result.stdout or ""), (result.stderr or "")  # код/выводы [1]

async def run_step(send, title: str, coro):
    await send(f"— {title} —")  # заголовок шага 
    try:
        rc, out, err = await coro  # выполняем подзадачу [1]
        if rc == 0:
            await send("Ок")  # краткий успех [4]
            return True
        else:
            tail_src = (err or out or "").strip().splitlines()[-3:]
            suffix = (": " + " | ".join(tail_src)) if tail_src else ""
            await send(f"Ошибка (код {rc}){suffix}")  # краткая ошибка [4]
            return False
    except Exception as e:
        await send(f"Ошибка: {e}")  # исключение шага [4]
        return False

async def run_and_stream(conn: asyncssh.SSHClientConnection, cmd: str, send, title: str = "", use_bash: bool = False) -> int:
    exec_cmd = cmd if not use_bash else f'/bin/bash -lc {sh_esc(cmd)}'  # запуск через bash -lc [1]
    if title:
        await send(f"— {title} —")  # секция 
    async with conn.create_process(exec_cmd) as proc:
        async for line in proc.stdout:
            if ("=== [" in line) or ("Ок" in line) or ("Ошибка" in line):
                await send(line.strip())  # только маркеры 
        rc = await proc.wait()
    await send("Ок" if rc == 0 else f"Ошибка (код {rc})")  # финальный статус по коду [4]
    return rc  # код возврата [1]

# ================= Выполнение на удалённом сервере =================
async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(text: str):
        chunk = text[-1800:] if len(text) > 1800 else text  # лимит сообщения [2]
        if chunk.strip():
            await interaction.followup.send(chunk, ephemeral=True)  # приватно в DM [2]

    await send("Подключение по SSH и проверка локали (UTF‑8)…")  # старт 
    conn_kwargs = dict(
        host=params["host"],
        username=params["user"],
        known_hosts=SSH_KNOWN_HOSTS,
        port=params["port"],
        password=params.get("password", None),
    )  # параметры asyncssh [1]

    try:
        async with asyncssh.connect(**conn_kwargs) as conn:  # SSH сессия [1]
            # 1) Локаль
            if QUIET:
                ok = await run_step(send, "Локаль", run_silent(conn, LOCALE_FIX, use_bash=True))  # кратко 
                if not ok:
                    return  # при ошибке прерываем [4]
            else:
                rc = await run_and_stream(conn, LOCALE_FIX, send, title="Локаль", use_bash=True)  # подробно 
                if rc != 0:
                    return  # при ошибке прерываем [4]

            # 2) Передача скрипта по SFTP (всегда кратко)
            await send("— Передача скрипта —")  # заголовок 
            try:
                content = await download_script(SCRIPT_URL)  # качаем на боте [3]
                await sftp_upload(conn, content, "setup_reboot.sh")  # отправляем по SFTP [1]
                await send("Ок")  # успех [4]
            except Exception as e:
                await send(f"Ошибка: {e}")  # краткая ошибка [4]
                return

            # 3) Запуск установки
            if mode == "final":
                run_cmd = f'./setup_reboot.sh --final --password {sh_esc(params["ss_password"])}'  # финальный 
            else:
                run_cmd = f'./setup_reboot.sh --forward-ip {sh_esc(params["forward_ip"])} --password {sh_esc(params["ss_password"])}'  # промежуточный 

            if QUIET:
                ok = await run_step(send, "Установка", run_silent(conn, run_cmd, use_bash=True))  # кратко [4]
                if not ok:
                    return  # при ошибке прерываем [4]
            else:
                rc = await run_and_stream(conn, run_cmd, send, title="Установка", use_bash=True)  # маркерный стрим [1]
                if rc != 0:
                    return  # при ошибке прерываем [4]

            # 4) После успеха сразу показать повторный выбор
            await interaction.followup.send("Выберите тип сервера:", view=RoleView(), ephemeral=True)  # новое меню [2]
    except Exception as e:
        await interaction.followup.send(f"Ошибка SSH/выполнения: {e}", ephemeral=True)  # ошибки подключения [1]

# ================= Инициализация и публикация кнопки =================
@bot.event
async def on_ready():
    try:
        await bot.tree.sync()  # синхронизация app-команд (на будущее) 
    except Exception as e:
        print("Slash sync error:", e)  # лог ошибки 
    print(f"Logged in as {bot.user}")  # подтверждение 
    if ALLOWED_CHANNEL_ID:
        ch = bot.get_channel(ALLOWED_CHANNEL_ID)
        if ch:
            try:
                await ch.send(
                    "Нажмите кнопку, чтобы начать приватный мастер настройки прокси.",
                    view=StartView()
                )  # публикация кнопки 
            except Exception as e:
                print("Failed to send start message:", e)  # лог публикации 

bot.run(TOKEN)  # запуск клиента 
