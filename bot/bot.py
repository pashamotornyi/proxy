#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, ipaddress, discord, asyncssh, aiohttp
from discord.ext import commands

# ===== Конфигурация =====
TOKEN = os.environ["DISCORD_BOT_TOKEN"]
SCRIPT_URL = os.environ["SCRIPT_URL"]
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}
ALLOW_ALL = os.environ.get("ALLOW_ALL", "") == "1"
TAIL_LOG_ON_ERROR = os.environ.get("TAIL_LOG_ON_ERROR", "")
SSH_KNOWN_HOSTS = None
BUILD_TAG = "bot-hard2-2025-09-18-17-05"

# ===== Discord клиент =====
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

# ===== Хелперы =====
def valid_ip(v: str) -> bool:
    try: ipaddress.ip_address(v); return True
    except Exception: return False

def sh_esc(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"

def user_allowed_ctx(interaction: discord.Interaction) -> bool:
    if ALLOW_ALL: return True
    if ALLOWED_USERS and interaction.user.id in ALLOWED_USERS: return True
    if interaction.guild:
        m = interaction.guild.get_member(interaction.user.id) or interaction.user
        if ALLOWED_ROLE and isinstance(m, discord.Member) and any(r.name == ALLOWED_ROLE for r in m.roles):
            return True
        return isinstance(m, discord.Member) and m.guild_permissions.administrator
    return False

# ===== UI =====
class RoleView(discord.ui.View):
    def __init__(self): super().__init__(timeout=600)
    @discord.ui.button(label="Промежуточный сервер", style=discord.ButtonStyle.secondary, custom_id="intermediate")
    async def inter(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IntermediateModal(title="Промежуточный сервер"))
    @discord.ui.button(label="Финальный сервер", style=discord.ButtonStyle.success, custom_id="final")
    async def final(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(FinalModal(title="Финальный сервер"))

class StartView(discord.ui.View):
    def __init__(self): super().__init__(timeout=None)
    @discord.ui.button(label="Начать настройку", style=discord.ButtonStyle.primary, custom_id="start_setup")
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not user_allowed_ctx(interaction):
            await interaction.response.send_message("Недостаточно прав для запуска мастера.", ephemeral=True); return
        await interaction.response.defer(ephemeral=True)
        dm = await interaction.user.create_dm()
        await dm.send("Выберите тип сервера:", view=RoleView())
        await interaction.followup.send("Открыл личные сообщения.", ephemeral=True)

class IntermediateModal(discord.ui.Modal):
    def __init__(self, title: str):
        super().__init__(title=title)
        self.host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)
        self.ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)
        self.forward_ip = discord.ui.TextInput(label="IP следующего сервера", placeholder="5.6.7.8", required=True)
        self.ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)
        for c in (self.host, self.ssh_pass, self.forward_ip, self.ss_password): self.add_item(c)
    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        if not valid_ip(str(self.forward_ip.value)):
            return await interaction.followup.send("Некорректный forward_ip.", ephemeral=True)
        await run_remote_setup(interaction, "intermediate", dict(
            host=str(self.host.value), user="root", port=22, password=str(self.ssh_pass.value),
            forward_ip=str(self.forward_ip.value), ss_password=str(self.ss_password.value)
        ))

class FinalModal(discord.ui.Modal):
    def __init__(self, title: str):
        super().__init__(title=title)
        self.host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)
        self.ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)
        self.ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)
        for c in (self.host, self.ssh_pass, self.ss_password): self.add_item(c)
    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        await run_remote_setup(interaction, "final", dict(
            host=str(self.host.value), user="root", port=22, password=str(self.ssh_pass.value),
            ss_password=str(self.ss_password.value)
        ))

# ===== Транспорт =====
async def download_script(url: str) -> bytes:
    async with aiohttp.ClientSession() as s:
        async with s.get(url, allow_redirects=True) as r:
            data = await r.read()
            if r.status != 200 or not data: raise RuntimeError(f"Download failed: HTTP {r.status}")
    t = data.decode("utf-8", "replace").replace("\r\n","\n").replace("\r","\n")
    if not t.startswith("#!"): raise RuntimeError("Downloaded content is not a script (no shebang)")
    return t.encode("utf-8")

async def sftp_upload(conn: asyncssh.SSHClientConnection, data: bytes, remote_path: str):
    async with conn.start_sftp_client() as sftp:
        async with sftp.open(remote_path, "wb") as f: await f.write(data)
    await conn.run(f"chmod +x {sh_esc(remote_path)}", check=True)

# ===== Выполнение =====
async def run_and_stream(conn: asyncssh.SSHClientConnection, cmd: str, send, title: str) -> int:
    await send(f"— {title} —")
    async with conn.create_process(cmd) as proc:
        async for raw in proc.stdout:
            line = raw.rstrip("\r\n")
            if line and line.lstrip().startswith("=== ["):
                await send(line.strip())
        rc = await proc.wait()
    await send(f"RC: {rc}")
    return rc

async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(msg: str):
        if msg.strip(): await interaction.followup.send(msg[-1800:], ephemeral=True)

    await send(f"Подключение по SSH… [{BUILD_TAG}]")
    try:
        async with asyncssh.connect(
            host=params["host"], username=params["user"], port=params.get("port",22),
            password=params.get("password"), known_hosts=SSH_KNOWN_HOSTS
        ) as conn:
            await send("— Передача скрипта —")
            content = await download_script(SCRIPT_URL)
            await sftp_upload(conn, content, "setup_reboot.sh")
            await send("Ок")

            run_cmd = (f"./setup_reboot.sh --final --password {sh_esc(params['ss_password'])}"
                       if mode == "final"
                       else f"./setup_reboot.sh --forward-ip {sh_esc(params['forward_ip'])} --password {sh_esc(params['ss_password'])}")

            rc = await run_and_stream(conn, run_cmd, send, "Установка")
            if rc != 0:
                if TAIL_LOG_ON_ERROR:
                    _, out, err = await conn.run(f"tail -n 80 {sh_esc(TAIL_LOG_ON_ERROR)}", check=False)
                    snip = (err or out or "").strip()
                    if snip: await send("Последние строки лога:\n" + snip[-1700:])
                return

            # Успех: объединённое сообщение + ребут + новое меню под защитой
            try:
                await send("— STEP_END —\n— Перезагрузка сервера через 15 секунд —\nГотово. Сервер перезагрузится; подождите 1–2 минуты.")
                await conn.run("nohup sh -c 'sleep 15; systemctl reboot' >/dev/null 2>&1 &", check=False)
                await interaction.followup.send("Выберите тип сервера:", view=RoleView(), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(f"POST-OK error: {e}", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"Ошибка SSH/выполнения: {e}", ephemeral=True)

# ===== Запуск =====
@bot.event
async def on_ready():
    print(f"Starting ProxySetup HARD2, {BUILD_TAG}")
    if ALLOWED_CHANNEL_ID:
        ch = bot.get_channel(ALLOWED_CHANNEL_ID)
        if ch:
            await ch.send("Нажмите кнопку, чтобы начать приватный мастер настройки прокси.", view=StartView())

if __name__ == "__main__":
    bot.run(TOKEN)
