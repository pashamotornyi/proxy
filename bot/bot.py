#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ipaddress
import discord
from discord.ext import commands
import asyncssh
import aiohttp  # requirements: aiohttp>=3.9

# ================= Конфигурация окружения =================
TOKEN = os.environ["DISCORD_BOT_TOKEN"]            # токен бота [3]
SCRIPT_URL = os.environ["SCRIPT_URL"]              # RAW URL на setup_reboot.sh [5]
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))  # канал для кнопки [3]
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")                    # имя роли (опц.) [3]
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}  # белый список ID [3]
ALLOW_ALL = os.environ.get("ALLOW_ALL", "") == "1"  # разрешить всем (отладка) [3]
QUIET = os.environ.get("QUIET", "") == "1"          # тихий режим статусов [3]

SSH_KNOWN_HOSTS = None  # для продакшена задайте known_hosts/проверку host key [6]

# ================= Discord клиент =================
intents = discord.Intents.default()  # для UI достаточно default [3]
bot = commands.Bot(command_prefix="!", intents=intents)  # основной клиент [3]

# ================= Вспомогательные функции =================
def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v); return True
    except Exception:
        return False  # простая валидация IPv4/IPv6 [3]

def sh_esc(s: str) -> str:
    return '"' + s.replace('"', '\\"') + '"'  # безопасная цитата для bash -lc [3]

def user_allowed_ctx(interaction: discord.Interaction) -> bool:
    if ALLOW_ALL:
        return True  # принудительный допуск [3]
    if ALLOWED_USERS and interaction.user.id in ALLOWED_USERS:
        return True  # белый список [3]
    if interaction.guild:
        member = interaction.guild.get_member(interaction.user.id) or interaction.user
        if ALLOWED_ROLE and isinstance(member, discord.Member) and any(r.name == ALLOWED_ROLE for r in member.roles):
            return True  # роль [3]
        return isinstance(member, discord.Member) and member.guild_permissions.administrator  # админ [3]
    if ALLOWED_CHANNEL_ID:
        ch = interaction.client.get_channel(ALLOWED_CHANNEL_ID)
        guild = getattr(ch, "guild", None)
        if guild:
            member = guild.get_member(interaction.user.id)
            if member:
                if ALLOWED_ROLE and any(r.name == ALLOWED_ROLE for r in member.roles):
                    return True  # роль [3]
                return member.guild_permissions.administrator  # админ [3]
    return False  # запрет [3]

# ================= Облегчённая настройка UTF‑8 =================
LOCALE_FIX = r"""
# Lightweight UTF-8 setup (no apt, no hard failures)
set -Eeuo pipefail

# 1) Temporary session exports (effective immediately)
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANGUAGE=en_US:en

# 2) Persist defaults if possible (ignore errors on locked/minimal systems)
{ echo 'LANG=en_US.UTF-8'; echo 'LC_ALL=en_US.UTF-8'; echo 'LANGUAGE=en_US:en'; } > /etc/default/locale 2>/dev/null || true

# 3) If locale-gen exists, ensure mapping and generate quietly
if command -v locale-gen >/dev/null 2>&1; then
  grep -qE '^[# ]*en_US\.UTF-8 UTF-8' /etc/locale.gen 2>/dev/null || \
    echo 'en_US.UTF-8 UTF-8' >> /etc/locale.gen 2>/dev/null || true
  locale-gen en_US.UTF-8 >/dev/null 2>&1 || true
fi

# 4) Apply via update-locale if present
if command -v update-locale >/dev/null 2>&1; then
  update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 LANGUAGE=en_US:en >/dev/null 2>&1 || true
fi

# 5) Short confirmation
echo '--- locale (first lines) ---'
locale | sed -n '1,8p' || true
"""  # задаёт UTF‑8 на сессию и старается записать системно, без apt и жёстких падений [2]

# ================= UI: кнопки и модалки =================
class StartView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # без таймаута [3]

    @discord.ui.button(label="Начать настройку", style=discord.ButtonStyle.primary, custom_id="start_setup")
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not user_allowed_ctx(interaction):
            await interaction.response.send_message("Недостаточно прав для запуска мастера.", ephemeral=True)  # приватный отказ [3]
            return
        await interaction.response.defer(ephemeral=True)  # корректный эпемерный ответ перед followup [7]
        try:
            dm = await interaction.user.create_dm()
            await dm.send("Выберите тип сервера:", view=RoleView())  # переход в DM [3]
            await interaction.followup.send("Открыл личные сообщения.", ephemeral=True)  # уведомление [7]
        except discord.Forbidden:
            await interaction.followup.send("Не удалось написать в личные сообщения (закрыт DM).", ephemeral=True)  # обработка отказа [7]

class RoleView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)  # 10 минут [3]

    @discord.ui.button(label="Промежуточный сервер", style=discord.ButtonStyle.secondary, custom_id="intermediate")
    async def inter(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IntermediateModal(title="Промежуточный сервер"))  # модалка [3]

    @discord.ui.button(label="Финальный сервер", style=discord.ButtonStyle.success, custom_id="final")
    async def final(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(FinalModal(title="Финальный сервер"))  # модалка [3]

class IntermediateModal(discord.ui.Modal, title="Промежуточный сервер"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)  # [3]
    ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)  # [3]
    forward_ip = discord.ui.TextInput(label="IP следующего сервера", placeholder="5.6.7.8", required=True)  # [3]
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)  # [3]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [3]
        if not valid_ip(str(self.forward_ip)):
            return await interaction.followup.send("Некорректный forward_ip.", ephemeral=True)  # валидация [3]
        params = dict(
            host=str(self.host), user="root", port=22,
            password=str(self.ssh_pass),
            forward_ip=str(self.forward_ip),
            ss_password=str(self.ss_password),
        )  # параметры [3]
        await run_remote_setup(interaction, mode="intermediate", params=params)  # запуск [3]

class FinalModal(discord.ui.Modal, title="Финальный сервер"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)  # [3]
    ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)  # [3]
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)  # [3]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [3]
        params = dict(
            host=str(self.host), user="root", port=22,
            password=str(self.ssh_pass),
            ss_password=str(self.ss_password),
        )  # параметры [3]
        await run_remote_setup(interaction, mode="final", params=params)  # запуск [3]

# ================= Загрузка и передача файла по SFTP =================
async def download_script(url: str) -> bytes:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, allow_redirects=True) as resp:
            data = await resp.read()
            if resp.status != 200 or not data:
                raise RuntimeError(f"Download failed: HTTP {resp.status}")  # защита [5]
    text = data.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    if not text.startswith("#!"):
        raise RuntimeError("Downloaded content is not a script (no shebang)")  # валидация [5]
    return text.encode("utf-8")  # нормализованный UTF‑8 [5]

async def sftp_upload(conn: asyncssh.SSHClientConnection, data: bytes, remote_path: str) -> None:
    async with conn.start_sftp_client() as sftp:
        async with sftp.open(remote_path, "wb") as f:
            await f.write(data)  # запись bytes [1]
    await conn.run(f"chmod +x {sh_esc(remote_path)}", check=True)  # chmod [1]

# ================= Исполнители шагов (успех строго по rc) =================
async def run_silent(conn: asyncssh.SSHClientConnection, cmd: str, use_bash: bool = False):
    exec_cmd = cmd if not use_bash else f'/bin/bash -lc {sh_esc(cmd)}'  # единый запуск [1]
    result = await conn.run(exec_cmd, check=False)  # без исключений [1]
    return result.exit_status, (result.stdout or ""), (result.stderr or "")  # возврат rc/out/err [1]

async def run_step(send, title: str, coro):
    await send(f"— {title} —")  # заголовок [3]
    try:
        rc, out, err = await coro
        if rc == 0:
            await send("Ок")  # успех по rc [1]
            return True
        tail_src = (err or out or "").strip().splitlines()[-3:]
        suffix = (": " + " | ".join(tail_src)) if tail_src else ""
        await send(f"Ошибка (код {rc}){suffix}")  # краткий контекст [1]
        return False
    except Exception as e:
        await send(f"Ошибка: {e}")  # исключение шага [1]
        return False

async def run_and_stream(conn: asyncssh.SSHClientConnection, cmd: str, send, title: str = "", use_bash: bool = False) -> int:
    exec_cmd = cmd if not use_bash else f'/bin/bash -lc {sh_esc(cmd)}'  # запуск [1]
    if title:
        await send(f"— {title} —")  # заголовок [3]
    async with conn.create_process(exec_cmd) as proc:
        async for line in proc.stdout:
            if ("=== [" in line) or ("Ок" in line) or ("Ошибка" in line):
                await send(line.strip())  # маркеры [3]
        rc = await proc.wait()
    await send("Ок" if rc == 0 else f"Ошибка (код {rc})")  # статус по rc [1]
    return rc  # возврат кода [1]

# ================= Выполнение на удалённом сервере =================
async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(text: str):
        chunk = text[-1800:] if len(text) > 1800 else text
        if chunk.strip():
            await interaction.followup.send(chunk, ephemeral=True)  # followup после defer [7]

    await send("Подключение по SSH и проверка локали (UTF‑8)…")  # старт [1]
    conn_kwargs = dict(
        host=params["host"], username=params["user"],
        known_hosts=SSH_KNOWN_HOSTS, port=params["port"],
        password=params.get("password", None),
    )  # параметры AsyncSSH [6]

    try:
        async with asyncssh.connect(**conn_kwargs) as conn:
            # 1) Локаль — продолжаем ТОЛЬКО если rc==0
            if QUIET:
                ok = await run_step(send, "Локаль", run_silent(conn, LOCALE_FIX, use_bash=True))
                if not ok:
                    return
            else:
                rc = await run_and_stream(conn, LOCALE_FIX, send, title="Локаль", use_bash=True)
                if rc != 0:
                    return

            # 2) Передача скрипта
            await send("— Передача скрипта —")
            try:
                content = await download_script(SCRIPT_URL)  # скачиваем на боте [5]
                await sftp_upload(conn, content, "setup_reboot.sh")  # передаём по SFTP [1]
                await send("Ок")
            except Exception as e:
                await send(f"Ошибка: {e}")
                return

            # 3) Запуск установки
            if mode == "final":
                run_cmd = f'./setup_reboot.sh --final --password {sh_esc(params["ss_password"])}'  # финальный [3]
            else:
                run_cmd = f'./setup_reboot.sh --forward-ip {sh_esc(params["forward_ip"])} --password {sh_esc(params["ss_password"])}'  # промежуточный [3]

            if QUIET:
                ok = await run_step(send, "Установка", run_silent(conn, run_cmd, use_bash=True))
                if not ok:
                    return
            else:
                rc = await run_and_stream(conn, run_cmd, send, title="Установка", use_bash=True)
                if rc != 0:
                    return

            # 4) Повторное меню
            await interaction.followup.send("Выберите тип сервера:", view=RoleView(), ephemeral=True)  # новое меню [7]
    except Exception as e:
        await interaction.followup.send(f"Ошибка SSH/выполнения: {e}", ephemeral=True)  # общий перехват [7]

# ================= Инициализация и публикация кнопки =================
@bot.event
async def on_ready():
    try:
        await bot.tree.sync()  # синхронизация app-команд [3]
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
                )  # стартовое сообщение [3]
            except Exception as e:
                print("Failed to send start message:", e)

bot.run(TOKEN)  # запуск клиента [3]
