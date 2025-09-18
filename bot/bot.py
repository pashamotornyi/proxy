#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import ipaddress
import asyncio
import discord
from discord.ext import commands
import asyncssh
import aiohttp

TOKEN = os.environ["DISCORD_BOT_TOKEN"]
SCRIPT_URL = os.environ["SCRIPT_URL"]
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}
ALLOW_ALL = os.environ.get("ALLOW_ALL", "") == "1"
QUIET = os.environ.get("QUIET", "") == "1"
TAIL_LOG_ON_ERROR = os.environ.get("TAIL_LOG_ON_ERROR", "")
SSH_KNOWN_HOSTS = None

BUILD_TAG = "bot-verify-2025-09-18-16-10"

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v); return True
    except Exception:
        return False

def sh_esc(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"

def user_allowed_ctx(interaction: discord.Interaction) -> bool:
    if ALLOW_ALL: return True
    if ALLOWED_USERS and interaction.user.id in ALLOWED_USERS: return True
    if interaction.guild:
        member = interaction.guild.get_member(interaction.user.id) or interaction.user
        if ALLOWED_ROLE and isinstance(member, discord.Member) and any(r.name == ALLOWED_ROLE for r in member.roles):
            return True
        return isinstance(member, discord.Member) and member.guild_permissions.administrator
    if ALLOWED_CHANNEL_ID:
        ch = interaction.client.get_channel(ALLOWED_CHANNEL_ID)
        guild = getattr(ch, "guild", None)
        if guild:
            member = guild.get_member(interaction.user.id)
            if member:
                if ALLOWED_ROLE and any(r.name == ALLOWED_ROLE for r in member.roles):
                    return True
                return member.guild_permissions.administrator
    return False

class StartView(discord.ui.View):
    def __init__(self): super().__init__(timeout=None)
    @discord.ui.button(label="Начать настройку", style=discord.ButtonStyle.primary, custom_id="start_setup")
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not user_allowed_ctx(interaction):
            await interaction.response.send_message("Недостаточно прав для запуска мастера.", ephemeral=True); return
        await interaction.response.defer(ephemeral=True)
        try:
            dm = await interaction.user.create_dm()
            await dm.send("Выберите тип сервера:", view=RoleView())
            await interaction.followup.send("Открыл личные сообщения.", ephemeral=True)
        except discord.Forbidden:
            await interaction.followup.send("Не удалось написать в личные сообщения (закрыт DM).", ephemeral=True)

class RoleView(discord.ui.View):
    def __init__(self): super().__init__(timeout=600)
    @discord.ui.button(label="Промежуточный сервер", style=discord.ButtonStyle.secondary, custom_id="intermediate")
    async def inter(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IntermediateModal(title="Промежуточный сервер"))
    @discord.ui.button(label="Финальный сервер", style=discord.ButtonStyle.success, custom_id="final")
    async def final(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(FinalModal(title="Финальный сервер"))

class IntermediateModal(discord.ui.Modal):
    def __init__(self, title: str):
        super().__init__(title=title)
        self.host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)
        self.ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)
        self.forward_ip = discord.ui.TextInput(label="IP следующего сервера", placeholder="5.6.7.8", required=True)
        self.ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)
        for comp in (self.host, self.ssh_pass, self.forward_ip, self.ss_password):
            self.add_item(comp)
    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        if not valid_ip(str(self.forward_ip.value)):
            return await interaction.followup.send("Некорректный forward_ip.", ephemeral=True)
        params = dict(
            host=str(self.host.value), user="root", port=22,
            password=str(self.ssh_pass.value),
            forward_ip=str(self.forward_ip.value),
            ss_password=str(self.ss_password.value),
        )
        await run_remote_setup(interaction, mode="intermediate", params=params)

class FinalModal(discord.ui.Modal):
    def __init__(self, title: str):
        super().__init__(title=title)
        self.host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)
        self.ssh_pass = discord.ui.TextInput(label="SSH пароль", required=True)
        self.ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)
        for comp in (self.host, self.ssh_pass, self.ss_password):
            self.add_item(comp)
    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        params = dict(
            host=str(self.host.value), user="root", port=22,
            password=str(self.ssh_pass.value),
            ss_password=str(self.ss_password.value),
        )
        await run_remote_setup(interaction, mode="final", params=params)

async def download_script(url: str) -> bytes:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, allow_redirects=True) as resp:
            data = await resp.read()
            if resp.status != 200 or not data:
                raise RuntimeError(f"Download failed: HTTP {resp.status}")
    text = data.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    if not text.startswith("#!"):
        raise RuntimeError("Downloaded content is not a script (no shebang)")
    return text.encode("utf-8")

async def sftp_upload(conn: asyncssh.SSHClientConnection, data: bytes, remote_path: str) -> None:
    async with conn.start_sftp_client() as sftp:
        async with sftp.open(remote_path, "wb") as f:
            await f.write(data)
    await conn.run(f"chmod +x {sh_esc(remote_path)}", check=True)

async def run_silent(conn: asyncssh.SSHClientConnection, cmd: str):
    result = await conn.run(cmd, check=False)
    return result.exit_status, (result.stdout or ""), (result.stderr or "")

async def run_and_stream(conn: asyncssh.SSHClientConnection, cmd: str, send, title: str = "") -> int:
    if title:
        await send(f"— {title} —")
    async with conn.create_process(cmd) as proc:
        async for raw in proc.stdout:
            line = raw.rstrip("\r\n")
            if not line:
                continue
            if line.lstrip().startswith("=== ["):
                await send(line.strip())
        rc = await proc.wait()
    # Важно: при rc==0 всегда "Ок"
    if rc == 0:
        await send("Ок")
    else:
        await send(f"Ошибка (код {rc})")
    return rc

async def run_step(send, title: str, coro):
    await send(f"— {title} —")
    try:
        rc, out, err = await coro
        if rc == 0:
            await send("Ок"); return True
        tail_src = (err or out or "").strip().splitlines()[-3:]
        suffix = (": " + " | ".join(tail_src)) if tail_src else ""
        await send(f"Ошибка (код {rc}){suffix}"); return False
    except Exception as e:
        await send(f"Ошибка: {e}"); return False

async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(text: str):
        chunk = text[-1800:] if len(text) > 1800 else text
        if chunk.strip():
            await interaction.followup.send(chunk, ephemeral=True)

    await send(f"Подключение по SSH… [{BUILD_TAG}]")
    conn_kwargs = dict(
        host=params["host"], username=params["user"],
        known_hosts=SSH_KNOWN_HOSTS, port=params["port"],
        password=params.get("password", None),
    )

    try:
        async with asyncssh.connect(**conn_kwargs) as conn:
            await send("— Передача скрипта —")
            try:
                content = await download_script(SCRIPT_URL)
                await sftp_upload(conn, content, "setup_reboot.sh")
                await send("Ок")
            except Exception as e:
                await send(f"Ошибка: {e}"); return

            run_cmd = (
                f"./setup_reboot.sh --final --password {sh_esc(params['ss_password'])}"
                if mode == "final"
                else f"./setup_reboot.sh --forward-ip {sh_esc(params['forward_ip'])} --password {sh_esc(params['ss_password'])}"
            )

            rc = await run_and_stream(conn, run_cmd, send, title="Установка")
            if rc != 0:
                if TAIL_LOG_ON_ERROR:
                    tail_cmd = f"tail -n 80 {sh_esc(TAIL_LOG_ON_ERROR)}"
                    _, tail_out, tail_err = await run_silent(conn, tail_cmd)
                    snippet = (tail_err or tail_out or "").strip()
                    if snippet:
                        await send("Последние строки лога:\n" + snippet[-1700:])
                return

            # Гарантийный маркер и ребут
            await send("— STEP_END —")
            await send("— Перезагрузка сервера через 15 секунд —")
            await run_silent(conn, "nohup sh -c 'sleep 15; systemctl reboot' >/dev/null 2>&1 &")
            await send("Готово. Сервер перезагрузится; подождите 1–2 минуты.")
            await interaction.followup.send("Выберите тип сервера:", view=RoleView(), ephemeral=True)
            return

    except Exception as e:
        await interaction.followup.send(f"Ошибка SSH/выполнения: {e}", ephemeral=True)

@bot.event
async def on_ready():
    try:
        await bot.tree.sync()
    except Exception as e:
        print("Slash sync error:", e)
    print(f"Starting ProxySetup, {BUILD_TAG}")
    print(f"Logged in as {bot.user}")
    if ALLOWED_CHANNEL_ID:
        ch = bot.get_channel(ALLOWED_CHANNEL_ID)
        if ch:
            try:
                await ch.send(
                    "Нажмите кнопку, чтобы начать приватный мастер настройки прокси.",
                    view=StartView()
                )
            except Exception as e:
                print("Failed to send start message:", e)

if __name__ == "__main__":
    bot.run(TOKEN)
