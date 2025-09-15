#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import asyncio
import ipaddress
import discord
from discord.ext import commands
import asyncssh

# ================= Конфигурация через переменные окружения =================
TOKEN = os.environ["DISCORD_BOT_TOKEN"]  # токен бота (обязателен) [1]
SCRIPT_URL = os.environ["SCRIPT_URL"]    # RAW URL на setup_reboot.sh (обязателен) [1]
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))  # канал с кнопкой [1]
ALLOWED_ROLE = os.environ.get("ALLOWED_ROLE", "")                    # имя роли (опционально) [1]
ALLOWED_USERS = {int(x) for x in os.environ.get("ALLOWED_USERS", "").split(",") if x.strip().isdigit()}  # белый список ID [1]
ALLOW_ALL = os.environ.get("ALLOW_ALL", "") == "1"  # режим разрешить всем (для отладки) [1]

SSH_KNOWN_HOSTS = None  # для продакшена задайте файл известных хостов/строгую проверку ключей [2]

# ================= Discord bot =================
intents = discord.Intents.default()  # для slash/компонентов default достаточно [1]
bot = commands.Bot(command_prefix="!", intents=intents)  # префикс не используется, всё через компоненты [1]

# ================= Утилиты =================
def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except Exception:
        return False  # простая валидация IPv4/IPv6 [4]

def sh_esc(s: str) -> str:
    return '"' + s.replace('"', '\\"') + '"'  # безопасная цитата аргументов для /bin/bash -lc [4]

def user_allowed_ctx(interaction: discord.Interaction) -> bool:
    # 1) Грубый разрешающий флаг (отладка/экстренный доступ) [1]
    if ALLOW_ALL:
        return True  # включите ALLOW_ALL=1 в .env, чтобы отключить проверки временно [1]
    # 2) Белый список ID (если задан) [1]
    if ALLOWED_USERS and interaction.user.id in ALLOWED_USERS:
        return True  # явное разрешение по ID пользователя [1]
    # 3) Если событие пришло из гильдии — проверяем роли/админа [1]
    if interaction.guild:
        member = interaction.guild.get_member(interaction.user.id) or interaction.user  # вытаскиваем членство [1]
        if ALLOWED_ROLE and isinstance(member, discord.Member) and any(r.name == ALLOWED_ROLE for r in member.roles):
            return True  # у пользователя есть требуемая роль [1]
        return isinstance(member, discord.Member) and member.guild_permissions.administrator  # по умолчанию допускаем только администраторов [1]
    # 4) Если DM — пробуем вычислить гильдию через канал с кнопкой [1]
    if ALLOWED_CHANNEL_ID:
        ch = interaction.client.get_channel(ALLOWED_CHANNEL_ID)  # канал с кнопкой [1]
        guild = getattr(ch, "guild", None)  # берём гильдию из канала [1]
        if guild:
            member = guild.get_member(interaction.user.id)  # ищем участника в гильдии [1]
            if member:
                if ALLOWED_ROLE and any(r.name == ALLOWED_ROLE for r in member.roles):
                    return True  # роль допущена [1]
                return member.guild_permissions.administrator  # разрешаем администраторам [1]
    # 5) Нет информации — запрет по умолчанию [1]
    return False  # безопасное поведение: deny by default [1]

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
"""  # идемпотентная настройка en_US.UTF‑8 + демонстрация первых строк locale [3][5]

# ================= Представления (кнопки/модалки) =================
class StartView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # без таймаута, чтобы кнопка жила дольше в канале [1]

    @discord.ui.button(label="Начать настройку", style=discord.ButtonStyle.primary, custom_id="start_setup")
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not user_allowed_ctx(interaction):
            await interaction.response.send_message("Недостаточно прав для запуска мастера.", ephemeral=True)  # приватное уведомление [1]
            return  # блокируем неавторизованный старт [1]
        await interaction.response.defer(ephemeral=True)  # подтверждаем нажатие [1]
        try:
            dm = await interaction.user.create_dm()  # открываем DM [1]
            await dm.send("Выберите тип сервера:", view=RoleView())  # кнопки выбора сценария [1]
            await interaction.followup.send("Открыл личные сообщения.", ephemeral=True)  # фидбек в канале [1]
        except discord.Forbidden:
            await interaction.followup.send("Не удалось написать в личные сообщения (закрыт DM).", ephemeral=True)  # если у пользователя закрыты ЛС [1]

class RoleView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)  # 10 минут на выбор [1]

    @discord.ui.button(label="Промежуточный сервер", style=discord.ButtonStyle.secondary, custom_id="intermediate")
    async def inter(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IntermediateModal(title="Настройка промежуточного сервера"))  # модалка ввода параметров [1]

    @discord.ui.button(label="Финальный сервер", style=discord.ButtonStyle.success, custom_id="final")
    async def final(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(FinalModal(title="Настройка финального сервера"))  # модалка ввода параметров [1]

class IntermediateModal(discord.ui.Modal, title="Промежуточный"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)  # адрес сервера [1]
    ssh_user = discord.ui.TextInput(label="SSH пользователь", placeholder="root", default="root", required=True)  # имя пользователя [1]
    ssh_port = discord.ui.TextInput(label="SSH порт", placeholder="22", default="22", required=True)  # порт SSH [1]
    ssh_pass = discord.ui.TextInput(label="SSH пароль (оставьте пусто при ключе)", required=False, style=discord.TextStyle.short)  # пароль или пусто [1]
    forward_ip = discord.ui.TextInput(label="IP следующего сервера", placeholder="5.6.7.8", required=True)  # IP финального узла [1]
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)  # пароль SS [1]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # показываем индикатор [1]
        if not valid_ip(str(self.forward_ip)):
            await interaction.followup.send("Некорректный forward_ip.", ephemeral=True)  # валидация IP [4]
            return  # обрываем сценарий при невалидном IP [4]
        params = dict(
            host=str(self.host),
            user=str(self.ssh_user),
            port=int(str(self.ssh_port) or "22"),
            password=(str(self.ssh_pass) or None),
            forward_ip=str(self.forward_ip),
            ss_password=str(self.ss_password),
        )  # собираем параметры SSH и установки [1]
        await run_remote_setup(interaction, mode="intermediate", params=params)  # запускаем удалённую установку [1]

class FinalModal(discord.ui.Modal, title="Финальный"):
    host = discord.ui.TextInput(label="Хост (IP/домен)", placeholder="1.2.3.4", required=True)  # адрес сервера [1]
    ssh_user = discord.ui.TextInput(label="SSH пользователь", placeholder="root", default="root", required=True)  # имя пользователя [1]
    ssh_port = discord.ui.TextInput(label="SSH порт", placeholder="22", default="22", required=True)  # порт SSH [1]
    ssh_pass = discord.ui.TextInput(label="SSH пароль (оставьте пусто при ключе)", required=False)  # пароль или ключ [1]
    ss_password = discord.ui.TextInput(label="Пароль Shadowsocks", required=True, min_length=6, max_length=64)  # пароль SS [1]

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)  # индикатор [1]
        params = dict(
            host=str(self.host),
            user=str(self.ssh_user),
            port=int(str(self.ssh_port) or "22"),
            password=(str(self.ssh_pass) or None),
            ss_password=str(self.ss_password),
        )  # собираем параметры для финального узла [1]
        await run_remote_setup(interaction, mode="final", params=params)  # запускаем установку [1]

# ================= Исполнение на удалённом сервере =================
async def run_remote_setup(interaction: discord.Interaction, mode: str, params: dict):
    async def send(text: str):
        chunk = text[-1800:] if len(text) > 1800 else text  # Discord лимиты, режем до ~1800 символов [1]
        if chunk.strip():
            await interaction.followup.send(chunk, ephemeral=True)  # шлём в DM приватно [1]

    await send("Подключение по SSH и проверка локали (UTF‑8)…")  # статус о начале работ [3]
    conn_kwargs = dict(
        host=params["host"],
        username=params["user"],
        known_hosts=SSH_KNOWN_HOSTS,
        port=params["port"],
    )  # параметры подключения asyncssh [2]
    if params.get("password"):
        conn_kwargs["password"] = params["password"]  # парольная аутентификация при отсутствии ключа [2]

    try:
        async with asyncssh.connect(**conn_kwargs) as conn:  # устанавливаем SSH-сессию [2]
            # 1) Фикс локали UTF‑8
            rc1 = await run_and_stream(conn, LOCALE_FIX, send, title="Локаль")  # идемпотентный фикс en_US.UTF‑8 [3]
            if rc1 != 0:
                await send(f"Локаль: завершено с кодом {rc1}, продолжаем установку.")  # не критично — продолжаем [3]
            # 2) Загрузка и «очистка» скрипта
            fetch_cmd = f'curl -fsSL "{SCRIPT_URL}" | sed \'s/\\r$//\' > setup_reboot.sh && chmod +x setup_reboot.sh'  # удаляем CRLF на лету [1]
            rc2 = await run_and_stream(conn, fetch_cmd, send, title="Загрузка скрипта")  # качаем RAW и делаем исполняемым [1]
            if rc2 != 0:
                await send(f"Ошибка загрузки скрипта, код {rc2}.")  # прерываем при ошибке загрузки [1]
                return  # выходим из сценария [1]
            # 3) Формируем запуск
            if mode == "final":
                run_cmd = f'./setup_reboot.sh --final --password {sh_esc(params["ss_password"])}'  # запуск финального узла [1]
            else:
                run_cmd = f'./setup_reboot.sh --forward-ip {sh_esc(params["forward_ip"])} --password {sh_esc(params["ss_password"])}'  # запуск промежуточного узла [1]
            await send("Запускаю установку, это может занять 5–10 минут…")  # предупреждаем о длительности [1]
            rc3 = await run_and_stream(conn, run_cmd, send, title="Установка", use_bash=True)  # стримим шаги/статусы [6]
            await send(f"Готово. Код возврата: {rc3}")  # финальный отчёт [6]
    except Exception as e:
        await send(f"Ошибка SSH/выполнения: {e}")  # репорт любой исключительной ситуации [2]

async def run_and_stream(conn: asyncssh.SSHClientConnection, cmd: str, send, title: str = "", use_bash: bool = False) -> int:
    exec_cmd = cmd if not use_bash else f'/bin/bash -lc {sh_esc(cmd)}'  # для пайплайнов используем bash -lc [2]
    if title:
        await send(f"— {title} —")  # секционный заголовок для читаемости [1]
    async with conn.create_process(exec_cmd) as proc:  # создаём процесс на удалённой стороне [2]
        buf = []  # временный буфер строк [6]
        async for line in proc.stdout:
            buf.append(line)  # копим вывод построчно [6]
            if "=== [" in line or "Ок" in line or "Ошибка" in line or len(buf) >= 10:
                await send("".join(buf))  # отправляем пачками по событиям/объёму [6]
                buf.clear()  # очищаем буфер [6]
        if buf:
            await send("".join(buf))  # досылаем остатки [6]
        rc = await proc.wait()  # ждём завершение процесса [2]
        return rc  # возвращаем код возврата для отчёта [2]

# ================= Жизненный цикл бота =================
@bot.event
async def on_ready():
    try:
        await bot.tree.sync()  # синхронизируем slash-команды приложения (на будущее) [1]
    except Exception as e:
        print("Slash sync error:", e)  # диагностируем проблемы синхронизации [1]
    print(f"Logged in as {bot.user}")  # подтверждение авторизации [1]
    if ALLOWED_CHANNEL_ID:
        ch = bot.get_channel(ALLOWED_CHANNEL_ID)  # достаём канал по ID [1]
        if ch:
            try:
                await ch.send(
                    "Нажмите кнопку, чтобы начать приватный мастер настройки прокси.",  # поясняющее сообщение [1]
                    view=StartView()  # прикрепляем кнопку «Начать настройку» [1]
                )
            except Exception as e:
                print("Failed to send start message:", e)  # логируем ошибки публикации [1]

bot.run(TOKEN)  # старт основного цикла Discord клиента [1]
