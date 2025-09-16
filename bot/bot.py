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
TOKEN = os.environ["DISCORD_BOT_TOKEN"]                                # токен бота [4]
SCRIPT_URL = os.environ["SCRIPT_URL"]                                  # RAW URL на setup_reboot.sh [4]
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))    # канал для кнопки [4]
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")                      # имя роли (опц.) [4]
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}  # белый список ID [4]
ALLOW_ALL = os.environ.get("ALLOW_ALL", "") == "1"                     # разрешить всем (отладка) [4]
QUIET = os.environ.get("QUIET", "") == "1"                             # тихий режим статусов [4]
SSH_KNOWN_HOSTS = None  # для продакшена задайте known_hosts/проверку host key [3]

# ================= Discord клиент =================
intents = discord.Intents.default()                                    # для UI достаточно default [4]
bot = commands.Bot(command_prefix="!", intents=intents)                # основной клиент [4]

# ================= Вспомогательные функции =================
def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except Exception:
        return False  # простая валидация IPv4/IPv6 [4]

def sh_esc(s: str) -> str:
    # POSIX‑безопасное заключение в одинарные кавычки для аргументов
    return "'" + s.replace("'", "'\"'\"'") + "'"  # безопасно для путей/паролей [5]

def user_allowed_ctx(interaction: discord.Interaction) -> bool:
    if ALLOW_ALL:
        return True  # принудительный допуск [4]
    if ALLOWED_USERS and interaction.user.id in ALLOWED_USERS:
        return True  # белый список [4]
    if interaction.guild:
        member = interaction.guild.get_member(interaction.user.id) or interaction.user
        if ALLOWED_ROLE and isinstance(member, discord.Member) and any(r.name == ALLOWED_ROLE for r in member.roles):
            return True  # роль [4]
        return isinstance(member, discord.Member) and member.guild_permissions.administrator  # админ [4]
    if ALLOWED_CHANNEL_ID:
        ch = interaction.client.get_channel(ALLOWED_CHANNEL_ID)
        guild = getattr(ch, "guild", None)
        if guild:
            member = guild.get_member(interaction.user.id)
            if member:
                if ALLOWED_ROLE and any(r.name == ALLOWED_ROLE for r in member.roles):
                    return True  # роль [4]
                return member.guild_permissions.administrator  # админ [4]
    return False  # запрет [4]

# ================= UI: кнопки и модалки =================
class StartView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # без таймаута [6]

    @discord.ui.button(label="Начать настройку", style=discord.ButtonStyle.primary, custom_id="start_setup")
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not user_allowed_ctx(interaction):
            await interaction.response.send_message("Недостаточно прав для запуска мастера.", ephemeral=True)  # приватный отказ [6]
            return
        await interaction.response.defer(ephemeral=True)  # корректный defer перед followup [6]
        try:
            dm = await interaction.user.create_dm()
            await dm.send("Выберите тип сервера:", view=RoleView())  # переход в DM [6]
            await interaction.followup.send("Открыл личные сообщения.", ephemeral=True)  # уведомление [6]
        except discord.Forbidden:
            await interaction.followup.send("Не удалось написать в личные сообщения (закрыт DM).", ephemeral=True)  # обработка отказа [6]

class RoleView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)  # 10 минут [6]

    @discord.ui.button(label="Промежуточный сервер", style=discord.ButtonStyle.secondary, custom_id="intermediate")
    async def inter(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IntermediateModal(title="Промежуточный сервер"))  # модалка [6]

    @discord.ui.button(label="Финальный сервер", style=discord.ButtonStyle.success, custom_id="final")
    async def final(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(FinalModal(title="Финальный сервер"))  # модалка [6]

class IntermediateModal(discord.ui.Modal):
    def __init__(self, title: str):
        super().__init__(title=title)  # явная инициализация [6]
        self.host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)
        self.ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)
        self.forward_ip = discord.ui.TextInput(label="IP следующего сервера", placeholder="5.6.7.8", required=True)
        self.ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)
        for comp in (self.host, self.ssh_pass, self.forward_ip, self.ss_password):
            self.add_item(comp)  # стабильное добавление полей [6]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [6]
        if not valid_ip(str(self.forward_ip.value)):
            return await interaction.followup.send("Некорректный forward_ip.", ephemeral=True)  # валидация [6]
        params = dict(
            host=str(self.host.value), user="root", port=22,
            password=str(self.ssh_pass.value),
            forward_ip=str(self.forward_ip.value),
            ss_password=str(self.ss_password.value),
        )
        await run_remote_setup(interaction, mode="intermediate", params=params)  # запуск [4]

class FinalModal(discord.ui.Modal):
    def __init__(self, title: str):
        super().__init__(title=title)  # явная инициализация [6]
        self.host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)
        self.ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)
        self.ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)
        for comp in (self.host, self.ssh_pass, self.ss_password):
            self.add_item(comp)  # стабильное добавление полей [6]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [6]
        params = dict(
            host=str(self.host.value), user="root", port=22,
            password=str(self.ssh_pass.value),
            ss_password=str(self.ss_password.value),
        )
        await run_remote_setup(interaction, mode="final", params=params)  # запуск [4]

# ================= Загрузка и передача файла по SFTP =================
async def download_script(url: str) -> bytes:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, allow_redirects=True) as resp:
            data = await resp.read()
            if resp.status != 200 or not data:
                raise RuntimeError(f"Download failed: HTTP {resp.status}")  # защита [4]
    text = data.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    if not text.startswith("#!"):
        raise RuntimeError("Downloaded content is not a script (no shebang)")  # валидация [4]
    return text.encode("utf-8")  # нормализованный UTF‑8 [4]

async def sftp_upload(conn: asyncssh.SSHClientConnection, data: bytes, remote_path: str) -> None:
    async with conn.start_sftp_client() as sftp:
        async with sftp.open(remote_path, "wb") as f:
            await f.write(data)  # запись bytes по SFTP [3]
    await conn.run(f"chmod +x {sh_esc(remote_path)}", check=True)  # делаем исполняемым [3]

# ================= Исполнители шагов =================
async def run_silent(conn: asyncssh.SSHClientConnection, cmd: str):
    result = await conn.run(cmd, check=False)
    return result.exit_status, (result.stdout or ""), (result.stderr or "")  # rc/out/err [3]

async def run_and_stream(conn: asyncssh.SSHClientConnection, cmd: str, send, title: str = "") -> int:
    if title:
        await send(f"— {title} —")  # заголовок [4]
    async with conn.create_process(cmd) as proc:
        async for line in proc.stdout:
            # Показываем только маркеры шагов из скрипта, подавляя подробный вывод
            if line.startswith("=== ["):
                await send(line.strip())  # маркеры [3]
        rc = await proc.wait()
    # Успех строго по коду возврата:
    await send("Ок" if rc == 0 else f"Ошибка (код {rc})")  # без ложных "Ошибка ... rc:0" [3]
    return rc

async def run_step(send, title: str, coro):
    await send(f"— {title} —")  # заголовок секции [4]
    try:
        rc, out, err = await coro
        if rc == 0:
            await send("Ок")  # успех — stderr игнорируем [3]
            return True
        tail_src = (err or out or "").strip().splitlines()[-3:]
        suffix = (": " + " | ".join(tail_src)) if tail_src else ""
        await send(f"Ошибка (код {rc}){suffix}")  # краткий контекст [3]
        return False
    except Exception as e:
        await send(f"Ошибка: {e}")  # исключение [3]
        return False

# ================= Выполнение на удалённом сервере =================
async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(text: str):
        chunk = text[-1800:] if len(text) > 1800 else text
        if chunk.strip():
            await interaction.followup.send(chunk, ephemeral=True)  # followup после defer [6]

    await send("Подключение по SSH…")  # старт [3]
    conn_kwargs = dict(
        host=params["host"], username=params["user"],
        known_hosts=SSH_KNOWN_HOSTS, port=params["port"],
        password=params.get("password", None),
    )  # параметры AsyncSSH [3]

    try:
        async with asyncssh.connect(**conn_kwargs) as conn:  # SSH‑сессия [3]
            # 1) Передача скрипта
            await send("— Передача скрипта —")
            try:
                content = await download_script(SCRIPT_URL)  # скачиваем на боте [4]
                await sftp_upload(conn, content, "setup_reboot.sh")  # отправляем по SFTP [3]
                await send("Ок")
            except Exception as e:
                await send(f"Ошибка: {e}")
                return

            # 2) Запуск установки — однострочная команда
            if mode == "final":
                run_cmd = f"./setup_reboot.sh --final --password {sh_esc(params['ss_password'])}"
            else:
                run_cmd = f"./setup_reboot.sh --forward-ip {sh_esc(params['forward_ip'])} --password {sh_esc(params['ss_password'])}"

            # Стриминговый прогресс (видны только маркеры шагов):
            rc = await run_and_stream(conn, run_cmd, send, title="Установка")
            if rc != 0:
                return

            # 3) Считаем установку успешно завершённой и немедленно планируем ребут
            await send("Ок")  # финальный успех [3]
            await send("— Перезагрузка сервера через 15 секунд —")  # уведомление [1]
            await run_silent(conn, "nohup sh -c 'sleep 15; systemctl reboot' >/dev/null 2>&1 &")  # фоновый ребут [2]
            await send("Готово. Сервер перезагрузится; подождите 1–2 минуты.")  # информация [1]

            # 4) Сразу показываем новое меню для следующего процесса
            await interaction.followup.send("Выберите тип сервера:", view=RoleView(), ephemeral=True)  # новое меню [4]
            return

    except Exception as e:
        await interaction.followup.send(f"Ошибка SSH/выполнения: {e}", ephemeral=True)  # общий перехват [3]

# ================= Инициализация и публикация кнопки =================
@bot.event
async def on_ready():
    try:
        await bot.tree.sync()  # синхронизация app‑команд [6]
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
                )  # стартовое сообщение [6]
            except Exception as e:
                print("Failed to send start message:", e)

if __name__ == "__main__":
    bot.run(TOKEN)  # запуск клиента [4]
