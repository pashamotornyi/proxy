#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ipaddress
import asyncio
import discord
from discord.ext import commands
import asyncssh
import aiohttp

# ================= Конфигурация окружения =================
TOKEN = os.environ["DISCORD_BOT_TOKEN"]                                # токен бота [11]
SCRIPT_URL = os.environ["SCRIPT_URL"]                                  # RAW URL на setup_reboot.sh [11]
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))    # канал для кнопки [11]
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")                      # имя роли (опц.) [11]
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}  # белый список ID [11]
ALLOW_ALL = os.environ.get("ALLOW_ALL", "") == "1"                     # разрешить всем (отладка) [11]
QUIET = os.environ.get("QUIET", "") == "1"                             # тихий режим статусов [11]
REBOOT_AFTER_SETUP = os.environ.get("REBOOT_AFTER_SETUP", "1") == "1"  # автоперезагрузка после финальной установки [3]
SSH_KNOWN_HOSTS = None  # для продакшена задайте known_hosts/проверку host key [7]

# ================= Discord клиент =================
intents = discord.Intents.default()                                    # для UI достаточно default [11]
bot = commands.Bot(command_prefix="!", intents=intents)                # основной клиент [11]

# ================= Вспомогательные функции =================
def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except Exception:
        return False  # простая валидация IPv4/IPv6 [11]

def sh_esc(s: str) -> str:
    # POSIX‑безопасное заключение в одинарные кавычки для аргументов
    return "'" + s.replace("'", "'\"'\"'") + "'"  # безопасно для путей/паролей [8]

def user_allowed_ctx(interaction: discord.Interaction) -> bool:
    if ALLOW_ALL:
        return True  # принудительный допуск [11]
    if ALLOWED_USERS and interaction.user.id in ALLOWED_USERS:
        return True  # белый список [11]
    if interaction.guild:
        member = interaction.guild.get_member(interaction.user.id) or interaction.user
        if ALLOWED_ROLE and isinstance(member, discord.Member) and any(r.name == ALLOWED_ROLE for r in member.roles):
            return True  # роль [11]
        return isinstance(member, discord.Member) and member.guild_permissions.administrator  # админ [11]
    if ALLOWED_CHANNEL_ID:
        ch = interaction.client.get_channel(ALLOWED_CHANNEL_ID)
        guild = getattr(ch, "guild", None)
        if guild:
            member = guild.get_member(interaction.user.id)
            if member:
                if ALLOWED_ROLE and any(r.name == ALLOWED_ROLE for r in member.roles):
                    return True  # роль [11]
                return member.guild_permissions.administrator  # админ [11]
    return False  # запрет [11]

# ================= UI: кнопки и модалки =================
class StartView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # без таймаута [11]

    @discord.ui.button(label="Начать настройку", style=discord.ButtonStyle.primary, custom_id="start_setup")
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not user_allowed_ctx(interaction):
            await interaction.response.send_message("Недостаточно прав для запуска мастера.", ephemeral=True)  # приватный отказ [11]
            return
        await interaction.response.defer(ephemeral=True)  # корректный defer перед followup [11]
        try:
            dm = await interaction.user.create_dm()
            await dm.send("Выберите тип сервера:", view=RoleView())  # переход в DM [11]
            await interaction.followup.send("Открыл личные сообщения.", ephemeral=True)  # уведомление [11]
        except discord.Forbidden:
            await interaction.followup.send("Не удалось написать в личные сообщения (закрыт DM).", ephemeral=True)  # обработка отказа [11]

class RoleView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)  # 10 минут [11]

    @discord.ui.button(label="Промежуточный сервер", style=discord.ButtonStyle.secondary, custom_id="intermediate")
    async def inter(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IntermediateModal(title="Промежуточный сервер"))  # модалка [21]

    @discord.ui.button(label="Финальный сервер", style=discord.ButtonStyle.success, custom_id="final")
    async def final(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(FinalModal(title="Финальный сервер"))  # модалка [21]

class IntermediateModal(discord.ui.Modal):
    def __init__(self, title: str):
        super().__init__(title=title)  # явная инициализация [21]
        self.host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)
        self.ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)
        self.forward_ip = discord.ui.TextInput(label="IP следующего сервера", placeholder="5.6.7.8", required=True)
        self.ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)
        for comp in (self.host, self.ssh_pass, self.forward_ip, self.ss_password):
            self.add_item(comp)  # стабильное добавление полей [21]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [21]
        if not valid_ip(str(self.forward_ip.value)):
            return await interaction.followup.send("Некорректный forward_ip.", ephemeral=True)  # валидация [21]
        params = dict(
            host=str(self.host.value), user="root", port=22,
            password=str(self.ssh_pass.value),
            forward_ip=str(self.forward_ip.value),
            ss_password=str(self.ss_password.value),
        )
        await run_remote_setup(interaction, mode="intermediate", params=params)  # запуск [11]

class FinalModal(discord.ui.Modal):
    def __init__(self, title: str):
        super().__init__(title=title)  # явная инициализация [21]
        self.host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)
        self.ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)
        self.ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)
        for comp in (self.host, self.ssh_pass, self.ss_password):
            self.add_item(comp)  # стабильное добавление полей [21]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [21]
        params = dict(
            host=str(self.host.value), user="root", port=22,
            password=str(self.ssh_pass.value),
            ss_password=str(self.ss_password.value),
        )
        await run_remote_setup(interaction, mode="final", params=params)  # запуск [11]

# ================= Загрузка и передача файла по SFTP =================
async def download_script(url: str) -> bytes:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, allow_redirects=True) as resp:
            data = await resp.read()
            if resp.status != 200 or not data:
                raise RuntimeError(f"Download failed: HTTP {resp.status}")  # защита [11]
    text = data.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    if not text.startswith("#!"):
        raise RuntimeError("Downloaded content is not a script (no shebang)")  # валидация [11]
    return text.encode("utf-8")  # нормализованный UTF‑8 [11]

async def sftp_upload(conn: asyncssh.SSHClientConnection, data: bytes, remote_path: str) -> None:
    async with conn.start_sftp_client() as sftp:
        async with sftp.open(remote_path, "wb") as f:
            await f.write(data)  # запись bytes по SFTP [7]
    await conn.run(f"chmod +x {sh_esc(remote_path)}", check=True)  # делаем исполняемым [7]

# ================= Исполнители шагов =================
async def run_silent(conn: asyncssh.SSHClientConnection, cmd: str):
    result = await conn.run(cmd, check=False)
    return result.exit_status, (result.stdout or ""), (result.stderr or "")  # rc/out/err [7]

async def run_and_stream(conn: asyncssh.SSHClientConnection, cmd: str, send, title: str = "") -> int:
    if title:
        await send(f"— {title} —")  # заголовок [11]
    async with conn.create_process(cmd) as proc:
        async for line in proc.stdout:
            if "=== [" in line:
                await send(line.strip())  # транслируем только маркеры прогресса [7]
        rc = await proc.wait()
    await send("Ок" if rc == 0 else f"Ошибка (код {rc})")  # финальный статус по rc [7]
    return rc  # rc наружу [7]

async def run_step(send, title: str, coro):
    await send(f"— {title} —")  # заголовок секции [11]
    try:
        rc, out, err = await coro
        if rc == 0:
            await send("Ок")  # успех — stderr игнорируем [7]
            return True
        tail_src = (err or out or "").strip().splitlines()[-3:]
        suffix = (": " + " | ".join(tail_src)) if tail_src else ""
        await send(f"Ошибка (код {rc}){suffix}")  # краткий контекст при ошибке [7]
        return False
    except Exception as e:
        await send(f"Ошибка: {e}")  # исключение шага [7]
        return False

# ================= Выполнение на удалённом сервере =================
async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(text: str):
        chunk = text[-1800:] if len(text) > 1800 else text
        if chunk.strip():
            await interaction.followup.send(chunk, ephemeral=True)  # followup после defer [11]

    await send("Подключение по SSH…")  # старт [7]
    conn_kwargs = dict(
        host=params["host"], username=params["user"],
        known_hosts=SSH_KNOWN_HOSTS, port=params["port"],
        password=params.get("password", None),
    )  # параметры AsyncSSH [7]

    try:
        async with asyncssh.connect(**conn_kwargs) as conn:  # SSH‑сессия [7]
            # 1) Передача скрипта
            await send("— Передача скрипта —")
            try:
                content = await download_script(SCRIPT_URL)  # скачиваем на боте [11]
                await sftp_upload(conn, content, "setup_reboot.sh")  # отправляем по SFTP [7]
                await send("Ок")
            except Exception as e:
                await send(f"Ошибка: {e}")
                return

            # 2) Запуск установки — однострочная команда
            if mode == "final":
                run_cmd = f"./setup_reboot.sh --final --password {sh_esc(params['ss_password'])}"
            else:
                run_cmd = f"./setup_reboot.sh --forward-ip {sh_esc(params['forward_ip'])} --password {sh_esc(params['ss_password'])}"

            if QUIET:
                ok = await run_step(send, "Установка", run_silent(conn, run_cmd))
                if not ok:
                    return
            else:
                rc = await run_and_stream(conn, run_cmd, send, title="Установка")
                if rc != 0:
                    return

            # 3) Перезагрузка по завершении финальной установки
            if REBOOT_AFTER_SETUP and mode == "final":
                await send("— Перезагрузка сервера через 15 секунд —")  # уведомление [3]
                # Плановая перезагрузка: 0.25 минуты ≈ 15 секунд
                await run_silent(conn, "shutdown -r +0.25 'Reboot after proxy setup'")  # запланировать [3]
                await send("Готово. Сервер перезагрузится; подождите 1–2 минуты и проверьте доступ.")
                return

            # 4) Повторное меню (если не перезагружаем)
            await interaction.followup.send("Выберите тип сервера:", view=RoleView(), ephemeral=True)  # новое меню [11]

    except Exception as e:
        await interaction.followup.send(f"Ошибка SSH/выполнения: {e}", ephemeral=True)  # общий перехват [7]

# ================= Инициализация и публикация кнопки =================
@bot.event
async def on_ready():
    try:
        await bot.tree.sync()  # синхронизация app‑команд [11]
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
                )  # стартовое сообщение [11]
            except Exception as e:
                print("Failed to send start message:", e)

if __name__ == "__main__":
    bot.run(TOKEN)  # запуск клиента [7]
