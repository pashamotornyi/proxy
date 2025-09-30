#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, asyncio, discord, asyncssh, aiohttp, logging
from discord.ext import commands

# ===== Конфигурация =====
TOKEN = os.environ["DISCORD_BOT_TOKEN"]
SCRIPT_URL = os.environ["SCRIPT_URL"]
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}
ALLOW_ALL = os.environ.get("ALLOW_ALL", "") == "1"

# Диагностика (включить "1" для подробного лога asyncssh)
ASYNCSSH_DEBUG = os.environ.get("ASYNCSSH_DEBUG", "") == "1"

# SSH параметры
SSH_PORTS = [22]
CONNECT_TIMEOUT = 25
LOGIN_TIMEOUT = 150
KEEPALIVE_INTERVAL = 15

# На время диагностики позволяем авто-подбор алгоритмов (None)
# KEX_ALGS = None
# CIPHERS  = None
# HOSTKEY_ALGS = None

# Совместимый набор по умолчанию
KEX_ALGS = ['curve25519-sha256','curve25519-sha256@libssh.org','diffie-hellman-group14-sha256']
CIPHERS  = ['chacha20-poly1305@openssh.com','aes256-gcm@openssh.com','aes128-gcm@openssh.com']
HOSTKEY_ALGS = ['ssh-ed25519','rsa-sha2-256','rsa-sha2-512']

BUILD_TAG = "bot-preflight-autoalgs-2025-09-30-14-25"

# Логирование
logging.basicConfig(level=logging.INFO)
if ASYNCSSH_DEBUG:
    logging.getLogger('asyncssh').setLevel(logging.DEBUG)
    asyncssh.set_log_level('DEBUG')
else:
    asyncssh.set_log_level('WARNING')

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
            host=str(self.host.value), user="root", port=None, password=str(self.ssh_pass.value),
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
            host=str(self.host.value), user="root", port=None, password=str(self.ssh_pass.value),
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

async def preflight_banner(host: str, port: int, interaction: discord.Interaction):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT)
        banner = await asyncio.wait_for(reader.readline(), timeout=10)
        try:
            txt = banner.decode(errors='ignore').strip()
        except Exception:
            txt = repr(banner)
        await interaction.followup.send(f"SSH banner {host}:{port}: {txt}", ephemeral=True)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception as e:
        await interaction.followup.send(f"SSH banner preflight failed {host}:{port}: {type(e).__name__}: {e}", ephemeral=True)

async def connect_resilient(host: str, username: str, password: str, interaction: discord.Interaction):
    last_exc = None
    for port in SSH_PORTS:
        # Баннер-префлайт, чтобы отделить сетевой этап
        await preflight_banner(host, port, interaction)
        for attempt in range(3):
            try:
                conn = await asyncssh.connect(
                    host=host, port=port, username=username, password=password,
                    known_hosts=None, client_keys=None,
                    connect_timeout=CONNECT_TIMEOUT, login_timeout=LOGIN_TIMEOUT,
                    keepalive_interval=KEEPALIVE_INTERVAL,
                    kex_algs=KEX_ALGS, encryption_algs=CIPHERS, server_host_key_algs=HOSTKEY_ALGS,
                    preferred_auth=['password','keyboard-interactive'],
                    client_version='SSH-2.0-OpenSSH_8.9p1'
                )
                try:
                    cipher = conn.get_extra_info('cipher'); kex = conn.get_extra_info('kex'); hostkeys = conn.get_server_host_key_algs()
                    await interaction.followup.send(
                        f"SSH negotiated {host}:{port} -> cipher={cipher}, kex={kex}, hostkey={hostkeys}",
                        ephemeral=True
                    )
                except Exception:
                    pass
                return conn
            except Exception as e:
                last_exc = e
                await interaction.followup.send(
                    f"[ssh] connect failed {host}:{port} try {attempt+1}: {type(e).__name__}: {e}",
                    ephemeral=True
                )
                await asyncio.sleep(1 + attempt)
    raise last_exc

# ===== Основная логика =====
async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(msg: str):
        if msg.strip(): await interaction.followup.send(msg[-1800:], ephemeral=True)

    await send(f"Подключение по SSH… [{BUILD_TAG}]")
    finished = False
    try:
        async with await connect_resilient(params["host"], params["user"], params.get("password",""), interaction) as conn:
            await send("— Передача скрипта —")
            try:
                content = await download_script(SCRIPT_URL)
                await sftp_upload(conn, content, "setup_reboot.sh")
                await send("Ок")
            except Exception as e:
                await send(f"Ошибка загрузки/передачи: {e}")
                return

            run_cmd = (f"./setup_reboot.sh --final --password {sh_esc(params['ss_password'])}"
                       if mode == "final"
                       else f"./setup_reboot.sh --forward-ip {sh_esc(params['forward_ip'])} --password {sh_esc(params['ss_password'])}")

            async with conn.create_process(run_cmd, term_type='xterm', term_size=(80, 24)) as proc:
                async def drain_stream(stream, is_err=False):
                    async for raw in stream:
                        line = raw.rstrip("\r\n")
                        if not line: continue
                        if line.startswith("==="):
                            await send(line)
                        elif "Настройка завершена. Перезагружаем сервер." in line:
                            nonlocal finished
                            finished = True
                            await send("Настройка завершена. Перезагружаем сервер.")
                            try:
                                dm = await interaction.user.create_dm()
                                await dm.send("Выберите тип сервера:", view=RoleView())
                            except Exception:
                                pass
                        elif is_err:
                            await send(f"[stderr] {line}")
                        else:
                            pass

                t_out = asyncio.create_task(drain_stream(proc.stdout, is_err=False))
                t_err = asyncio.create_task(drain_stream(proc.stderr, is_err=True))
                await asyncio.gather(t_out, t_err)
                await asyncio.sleep(2)
            return

    except Exception as e:
        txt = str(e)
        suppress = finished and ("Connection lost" in txt or "Disconnect" in txt or "EOF" in txt)
        if not suppress:
            await interaction.followup.send(f"Ошибка SSH/выполнения: {type(e).__name__}: {e}", ephemeral=True)

# ===== UI модалки (дубли) =====
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
            host=str(self.host.value), user="root", port=None, password=str(self.ssh_pass.value),
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
            host=str(self.host.value), user="root", port=None, password=str(self.ssh_pass.value),
            ss_password=str(self.ss_password.value)
        ))

# ===== Инициализация =====
@bot.event
async def on_ready():
    print(f"Starting ProxySetup PRELIGHT-AUTOALGS, {BUILD_TAG}")
    if ALLOWED_CHANNEL_ID:
        ch = bot.get_channel(ALLOWED_CHANNEL_ID)
        if ch:
            try:
                await ch.send("Нажмите кнопку, чтобы начать приватный мастер настройки прокси.", view=StartView())
            except Exception as e:
                print("Failed to send start message:", e)

if __name__ == "__main__":
    bot.run(TOKEN)
