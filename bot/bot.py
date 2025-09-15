#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import asyncio
import ipaddress
import discord
from discord.ext import commands
import asyncssh

# ================= Конфигурация окружения =================
TOKEN = os.environ["DISCORD_BOT_TOKEN"]            # токен бота (обязателен) [1]
SCRIPT_URL = os.environ["SCRIPT_URL"]              # RAW URL на setup_reboot.sh (обязателен) [1]
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))  # канал, где публикуется кнопка [1]
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")                    # имя роли для допуска (опционально) [1]
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}  # белый список ID (опционально) [1]
ALLOW_ALL = os.environ.get("ALLOW_ALL", "") == "1"  # режим разрешить всем (упрощённый старт) [1]

SSH_KNOWN_HOSTS = None  # при проде задайте файл known_hosts или управляемую проверку ключей [2]

# ================= Discord клиент =================
intents = discord.Intents.default()  # для компонентов/slash команд достаточно default [1]
bot = commands.Bot(command_prefix="!", intents=intents)  # префикс не используется; взаимодействуем через UI [1]

# ================= Вспомогательные функции =================
def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v); return True
    except Exception:
        return False  # простая валидация IPv4/IPv6 [4]

def sh_esc(s: str) -> str:
    return '"' + s.replace('"', '\\"') + '"'  # безопасная цитата для передачи параметров bash -lc [4]

def user_allowed_ctx(interaction: discord.Interaction) -> bool:
    if ALLOW_ALL:
        return True  # принудительный допуск для отладки/первого запуска [1]
    if ALLOWED_USERS and interaction.user.id in ALLOWED_USERS:
        return True  # явное разрешение по списку ID [1]
    if interaction.guild:
        member = interaction.guild.get_member(interaction.user.id) or interaction.user  # достаём объект участника в гильдии [1]
        if ALLOWED_ROLE and isinstance(member, discord.Member) and any(r.name == ALLOWED_ROLE for r in member.roles):
            return True  # у пользователя есть нужная роль [1]
        return isinstance(member, discord.Member) and member.guild_permissions.administrator  # по умолчанию допускаем администраторов [1]
    if ALLOWED_CHANNEL_ID:
        ch = interaction.client.get_channel(ALLOWED_CHANNEL_ID)  # канал из настроек [1]
        guild = getattr(ch, "guild", None)  # получаем гильдию из канала [1]
        if guild:
            member = guild.get_member(interaction.user.id)  # ищем участника в гильдии [1]
            if member:
                if ALLOWED_ROLE and any(r.name == ALLOWED_ROLE for r in member.roles):
                    return True  # роль допущена [1]
                return member.guild_permissions.administrator  # администратор — допуск [1]
    return False  # иначе запрет [1]

# ================= Фикс локали UTF‑8 на целевом сервере =================
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
"""  # идемпотентная настройка en_US.UTF‑8 и демонстрация текущих значений [3][5]

# ================= UI: кнопка в канале и модалки =================
class StartView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # без таймаута, чтобы сообщение жило [1]

    @discord.ui.button(label="Начать настройку", style=discord.ButtonStyle.primary, custom_id="start_setup")
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not user_allowed_ctx(interaction):
            await interaction.response.send_message("Недостаточно прав для запуска мастера.", ephemeral=True)  # приватный отказ [1]
            return  # прерываем без доступа [1]
        await interaction.response.defer(ephemeral=True)  # подтверждаем нажатие [1]
        try:
            dm = await interaction.user.create_dm()  # открываем ЛС [1]
            await dm.send("Выберите тип сервера:", view=RoleView())  # отправляем кнопки выбора [1]
            await interaction.followup.send("Открыл личные сообщения.", ephemeral=True)  # подтверждаем в канале [1]
        except discord.Forbidden:
            await interaction.followup.send("Не удалось написать в личные сообщения (закрыт DM).", ephemeral=True)  # DM закрыт [1]

class RoleView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)  # 10 минут на выбор [1]

    @discord.ui.button(label="Промежуточный сервер", style=discord.ButtonStyle.secondary, custom_id="intermediate")
    async def inter(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IntermediateModal(title="Промежуточный сервер"))  # открываем модалку [1]

    @discord.ui.button(label="Финальный сервер", style=discord.ButtonStyle.success, custom_id="final")
    async def final(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(FinalModal(title="Финальный сервер"))  # открываем модалку [1]

# Порядок полей важен: ssh_pass идёт вторым сразу после host
class IntermediateModal(discord.ui.Modal, title="Промежуточный сервер"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)  # 1 [6]
    ssh_pass = discord.ui.TextInput(label="SSH пароль (опционально при входе по ключу)", required=False)  # 2 [6]
    forward_ip = discord.ui.TextInput(label="IP следующего сервера", placeholder="5.6.7.8", required=True)  # 3 [6]
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)  # 4 [6]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор обработки [1]
        if not valid_ip(str(self.forward_ip)):
            return await interaction.followup.send("Некорректный forward_ip.", ephemeral=True)  # валидация IP [4]
        params = dict(
            host=str(self.host),
            user="root",   # по умолчанию root [1]
            port=22,       # по умолчанию 22 [1]
            password=(str(self.ssh_pass) or None),
            forward_ip=str(self.forward_ip),
            ss_password=str(self.ss_password),
        )  # собираем параметры запуска [1]
        await run_remote_setup(interaction, mode="intermediate", params=params)  # запускаем установку [1]

class FinalModal(discord.ui.Modal, title="Финальный сервер"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)  # 1 [6]
    ssh_pass = discord.ui.TextInput(label="SSH пароль (опционально при входе по ключу)", required=False)  # 2 [6]
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)  # 3 [6]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [1]
        params = dict(
            host=str(self.host),
            user="root",   # по умолчанию root [1]
            port=22,       # по умолчанию 22 [1]
            password=(str(self.ssh_pass) or None),
            ss_password=str(self.ss_password),
        )  # параметры для финального узла [1]
        await run_remote_setup(interaction, mode="final", params=params)  # запускаем установку [1]

# ================= Выполнение SSH-команд и стрим логов =================
async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(text: str):
        chunk = text[-1800:] if len(text) > 1800 else text  # обрезаем под лимиты Discord [1]
        if chunk.strip():
            await interaction.followup.send(chunk, ephemeral=True)  # отправляем в DM приватно [1]

    await send("Подключение по SSH и проверка локали (UTF‑8)…")  # сообщение о начале [3]
    conn_kwargs = dict(
        host=params["host"],
        username=params["user"],
        known_hosts=SSH_KNOWN_HOSTS,
        port=params["port"],
    )  # параметры asyncssh [2]
    if params.get("password"):
        conn_kwargs["password"] = params["password"]  # аутентификация паролем при отсутствии ключа [2]

    try:
        async with asyncssh.connect(**conn_kwargs) as conn:  # устанавливаем SSH-сессию [2]
            rc1 = await run_and_stream(conn, LOCALE_FIX, send, title="Локаль")  # идемпотентный фикс en_US.UTF‑8 [3]
            if rc1 != 0:
                await send(f"Локаль: завершено с кодом {rc1}, продолжаем установку.")  # информируем и продолжаем [3]
            fetch_cmd = f'curl -fsSL "{SCRIPT_URL}" | sed \'s/\\r$//\' > setup_reboot.sh && chmod +x setup_reboot.sh'  # загрузка RAW и удаление CRLF [1]
            rc2 = await run_and_stream(conn, fetch_cmd, send, title="Загрузка скрипта")  # качаем скрипт [1]
            if rc2 != 0:
                await send(f"Ошибка загрузки скрипта, код {rc2}.")  # прерываем на ошибке скачивания [1]
                return  # выходим [1]
            if mode == "final":
                run_cmd = f'./setup_reboot.sh --final --password {sh_esc(params["ss_password"])}'  # формируем команду [1]
            else:
                run_cmd = f'./setup_reboot.sh --forward-ip {sh_esc(params["forward_ip"])} --password {sh_esc(params["ss_password"])}'  # команда для промежуточного узла [1]
            await send("Запускаю установку, это может занять 5–10 минут…")  # предупреждаем [1]
            rc3 = await run_and_stream(conn, run_cmd, send, title="Установка", use_bash=True)  # стримим шаги [7]
            await send(f"Готово. Код возврата: {rc3}")  # отчёт о завершении [7]
    except Exception as e:
        await send(f"Ошибка SSH/выполнения: {e}")  # репорт исключений [2]

async def run_and_stream(conn: asyncssh.SSHClientConnection, cmd: str, send, title: str = "", use_bash: bool = False) -> int:
    exec_cmd = cmd if not use_bash else f'/bin/bash -lc {sh_esc(cmd)}'  # для пайплайнов используем bash -lc [2]
    if title:
        await send(f"— {title} —")  # секционный заголовок [1]
    async with conn.create_process(exec_cmd) as proc:  # создаём процесс на удалённой стороне [2]
        buf = []  # буфер вывода [7]
        async for line in proc.stdout:
            buf.append(line)  # собираем строки [7]
            if "=== [" in line or "Ок" in line or "Ошибка" in line or len(buf) >= 10:
                await send("".join(buf))  # отправляем порциями [7]
                buf.clear()  # чистим буфер [7]
        if buf:
            await send("".join(buf))  # досылаем остаток [7]
        rc = await proc.wait()  # дожидаемся завершения [2]
        return rc  # отдаём код возврата [2]

# ================= Инициализация и публикация кнопки =================
@bot.event
async def on_ready():
    try:
        await bot.tree.sync()  # синхронизация app-команд (на будущее) [1]
    except Exception as e:
        print("Slash sync error:", e)  # лог ошибки синхронизации [1]
    print(f"Logged in as {bot.user}")  # подтверждение входа [1]
    if ALLOWED_CHANNEL_ID:
        ch = bot.get_channel(ALLOWED_CHANNEL_ID)  # находим канал по ID [1]
        if ch:
            try:
                await ch.send(
                    "Нажмите кнопку, чтобы начать приватный мастер настройки прокси.",  # приглашение [1]
                    view=StartView()  # кнопка «Начать настройку» [1]
                )
            except Exception as e:
                print("Failed to send start message:", e)  # лог ошибки публикации [1]

bot.run(TOKEN)  # запуск клиента [1]
