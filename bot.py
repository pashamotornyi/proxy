#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, asyncio, ssl, socket, discord, asyncssh, aiohttp
from asyncssh.misc import DisconnectError, ConnectionLost
from discord.ext import commands

# ===== Конфигурация =====
TOKEN = os.environ["DISCORD_BOT_TOKEN"]
SCRIPT_URL = os.environ["SCRIPT_URL"]
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}
ALLOW_ALL = os.environ.get("ALLOW_ALL", "") == "1"

# SSH приоритет и тайминги
SSH_PORTS = [22, 2222]
CONNECT_TIMEOUT = 45
LOGIN_TIMEOUT = 90
KEEPALIVE_INTERVAL = 15

BUILD_TAG = "bot-ssh-socket-fix-no-kbdint-2025-09-29-16-12"

# ===== Discord клиент =====
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

# ===== Хелперы =====
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
        await run_remote_setup(interaction, "intermediate", dict(
            host=str(self.host.value), user="root", password=str(self.ssh_pass.value),
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
            host=str(self.host.value), user="root", password=str(self.ssh_pass.value),
            ss_password=str(self.ss_password.value)
        ))

# ===== Загрузка скрипта =====
async def download_script(url: str) -> bytes:
    async with aiohttp.ClientSession() as s:
        async with s.get(url, allow_redirects=True) as r:
            data = await r.read()
            if r.status != 200 or not data:
                raise RuntimeError(f"Download failed: HTTP {r.status}")
    t = data.decode("utf-8", "replace").replace("\r\n","\n").replace("\r","\n")
    if not t.startswith("#!"):
        raise RuntimeError("Downloaded content is not a script (no shebang)")
    return t.encode("utf-8")

async def sftp_upload(conn: asyncssh.SSHClientConnection, data: bytes, remote_path: str):
    async with conn.start_sftp_client() as sftp:
        async with sftp.open(remote_path, "wb") as f:
            await f.write(data)
    await conn.run(f"chmod +x {sh_esc(remote_path)}", check=True)

# ===== Подключение поверх готового TCP-сокета (IPv4) =====
def _fmt_exc(e: Exception) -> str:
    return f"{type(e).__name__}: {str(e) or '(no message)'}"

async def _open_tcp_ipv4(host: str, port: int, timeout: int) -> socket.socket:
    loop = asyncio.get_event_loop()
    infos = await loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    af, socktype, proto, _, sa = infos[0]
    s = socket.socket(af, socktype, proto)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(timeout)
    await loop.sock_connect(s, sa)
    return s

async def _connect_over_sock(sock: socket.socket, username: str, password: str):
    # Убраны kbd_interactive_auth/password_auth — asyncssh сам выберет методы
    return await asyncssh.connect(
        None,
        username=username,
        password=password,
        known_hosts=None,
        client_keys=None,
        connect_timeout=CONNECT_TIMEOUT,
        login_timeout=LOGIN_TIMEOUT,
        keepalive_interval=KEEPALIVE_INTERVAL,
        family=socket.AF_INET,
        sock=sock,
    )

async def connect_resilient(host: str, username: str, password: str):
    reasons = []

    for attempt in (1, 2):
        try:
            sock = await _open_tcp_ipv4(host, 22, CONNECT_TIMEOUT)
            try:
                return await _connect_over_sock(sock, username, password)
            except Exception as e:
                reasons.append(f"22/handshake{attempt}: {_fmt_exc(e)}")
                try: sock.close()
                except: pass
        except Exception as e:
            reasons.append(f"22/tcp{attempt}: {_fmt_exc(e)}")
        await asyncio.sleep(1.0)

    try:
        sock = await _open_tcp_ipv4(host, 2222, CONNECT_TIMEOUT)
        try:
            return await _connect_over_sock(sock, username, password)
        except Exception as e:
            reasons.append(f"2222/handshake: {_fmt_exc(e)}")
            try: sock.close()
            except: pass
    except Exception as e:
        reasons.append(f"2222/tcp: {_fmt_exc(e)}")

    raise RuntimeError("SSH не доступен. Подробности: " + " ; ".join(reasons))

# ===== Основной сценарий =====
async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(msg: str):
        if msg.strip():
            await interaction.followup.send(msg[-1800:], ephemeral=True)

    await send(f"Подключение по SSH… [{BUILD_TAG}]")
    finished = False
    try:
        async with await connect_resilient(params["host"], params["user"], params.get("password","")) as conn:
            await send("— Передача скрипта —")
            content = await download_script(SCRIPT_URL)
            await sftp_upload(conn, content, "setup_reboot.sh")
            await send("Ок")

            run_cmd = (f"./setup_reboot.sh --final --password {sh_esc(params['ss_password'])}"
                       if mode == "final"
                       else f"./setup_reboot.sh --forward-ip {sh_esc(params['forward_ip'])} --password {sh_esc(params['ss_password'])}")

            async with conn.create_process(run_cmd, term_type='xterm', term_size=(80, 24)) as proc:
                async for raw in proc.stdout:
                    line = raw.rstrip("\r\n")
                    if not line: continue
                    if line.startswith("==="):
                        await send(line)
                    elif "Настройка завершена. Перезагружаем сервер." in line:
                        finished = True
                        await send("Настройка завершена. Перезагружаем сервер.")
                        try:
                            dm = await interaction.user.create_dm()
#                            await dm.send("Настройка завершена. Перезагружаем сервер.")
                            await dm.send("Выберите тип сервера:", view=RoleView())
                        except Exception:
                            pass
                await asyncio.sleep(2)
            return

    except Exception as e:
        txt = str(e)
        suppress = finished and ("Connection lost" in txt or "Disconnect" in txt or "EOF" in txt)
        if not suppress:
            await interaction.followup.send(f"Ошибка SSH/выполнения: {e}", ephemeral=True)

# ===== Инициализация =====
@bot.event
async def on_ready():
    print(f"Starting ProxySetup socket-mode fixed, {BUILD_TAG}")
    if ALLOWED_CHANNEL_ID:
        ch = bot.get_channel(ALLOWED_CHANNEL_ID)
        if ch:
            try:
                await ch.send("Нажмите кнопку, чтобы начать приватный мастер настройки прокси.", view=StartView())
            except Exception as e:
                print("Failed to send start message:", e)

if __name__ == "__main__":
    bot.run(TOKEN)
