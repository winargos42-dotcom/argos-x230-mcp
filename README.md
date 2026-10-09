# ARGOS X230 MCP

**Открытая альтернатива удалённым desktop-командерам для Linux**: собственный MCP-сервер для ChatGPT и совместимых MCP-клиентов. Без коммерческого счётчика вызовов самого сервера. MIT License.

Этот проект вырос из рабочего моста ARGOS на ThinkPad X230 с Arch Linux. Это **не полный клон Desktop Commander**: мы сознательно ограничиваем удалённое выполнение команд, чтобы открытый сервер не превращался в незащищённый root-shell.

## Что уже реализовано

| Возможность | Инструмент / механизм |
|---|---|
| Проверка связи | `ping` |
| Диагностика Linux | `workstation_status`, `resource_status` |
| Просмотр файлов в workspace | `list_files`, `read_text` |
| Безопасная запись и точечный патч | `write_text`, `safe_patch` |
| Выполнение ограниченных диагностических действий | `run_safe_command` |
| Создание и список изолированных проектов | `project_create`, `project_list` |
| Git внутри конкретного проекта | `git_project` |
| Запуск Python unittest **без сети** в bubblewrap | `python_project_test` |
| Статус и ограниченные логи systemd | `service_health`, `service_logs` |
| Создание нового Cloudflare Tunnel через браузер | `argos-mcp-tunnel-wizard` (локальный мастер) |

Управление файлами строго ограничено отдельным каталогом. Git push/pull, произвольный shell, sudo/root-команды, запуск и остановка системных служб **не входят** в текущий API.

### Быстрый старт Linux (Python 3.11+)

```bash
git clone https://github.com/winargos42-dotcom/argos-x230-mcp.git
cd argos-x230-mcp
python3 -m venv .venv
.venv/bin/python -m pip install -e .
mkdir -p "$HOME/.config/argos-x230-mcp" "$HOME/argos-mcp-workspace"
chmod 700 "$HOME/.config/argos-x230-mcp" "$HOME/argos-mcp-workspace"
.venv/bin/python -c 'import secrets,pathlib,os; p=pathlib.Path.home()/".config/argos-x230-mcp/token"; p.write_text(secrets.token_urlsafe(48)); p.chmod(0o600); print("Private MCP token created")'
.venv/bin/python -m uvicorn argos_x230_mcp.server:app --host 127.0.0.1 --port 8765
```

Запускайте от обычного пользователя, **никогда от root**. На первом этапе сервер слушает только loopback, без публичного доступа. Локальный запрос без Bearer-токена обязан возвращать HTTP 401.

### Создание Cloudflare Tunnel через браузер

```bash
# cloudflared должен быть установлен отдельно; запуск — обычным пользователем
.venv/bin/argos-mcp-tunnel-wizard
.venv/bin/argos-mcp-install-desktop  # необязательный ярлык
```

Мастер открывает **локальную** страницу в браузере:
1. Открывает авторизацию Cloudflare, которую подтверждает владелец.
2. Создаёт новый именной туннель с уникальным ID, не затрагивая другие.
3. Формирует приватный YAML для маршрута на `127.0.0.1:8765`.
4. После подтверждения наличия Cloudflare Access создаёт DNS-запись.
5. Проверяет, что публичный адрес действительно перенаправляет на Cloudflare Access login.
6. **Только после проверки** может по отдельному нажатию создать и включить пользовательскую systemd-службу этого туннеля.

Мастер не перезаписывает существующий `/etc/cloudflared/config.yml` и не запрашивает секреты в ChatGPT. Браузерная авторизация/настройка политики Access требует действий владельца; автоматического обхода входа или 2FA нет.

**Важно:** для успешного доступа MCP через Cloudflare Access сервер должен получать `ARGOS_MCP_PUBLIC_HOSTNAME`, `ARGOS_CF_ACCESS_TEAM`, `ARGOS_CF_ACCESS_AUD` и `ARGOS_CF_ACCESS_EMAIL` из приватного окружения службы. Пока JWT не настроены, сервер работает только с локальным Bearer-токеном и **не принимает Access JWT**. Это безопасный отказ, а не ошибочная публикация.

Подробнее: [Пошаговая инструкция](docs/INSTALL_RU.md) · [Безопасность](SECURITY.md) · [Туннель в браузере](docs/BROWSER_TUNNEL_RU.md).

### Тесты

```bash
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m unittest discover -s tests -v
```

Тестирование выполняется локально без обращения к реальному Cloudflare и без создания туннелей: CLI и HTTP-команды подменяются безопасными заглушками. На X230 — **42/42 PASS** на момент первой публикации.

### Что с лимитами и стоимостью?

Сам ARGOS X230 MCP не имеет платы за вызовы, коммерческого счётчика или подписки. При этом **ChatGPT, Cloudflare, интернет и оборудование имеют собственные тарифы/ограничения**, на которые лицензия MIT не влияет.

### Статус проекта

Первый публичный выпуск: **v0.1 — Linux + MCP + безопасная локальная работа + браузерный Cloudflare Tunnel Wizard**.

Оставшиеся направления: фоновые задания с отдельным контролем cgroups, работа с процессами по capability-allowlist, безопасная синхронизация проектов, поддержка других ОС, полноценная end-to-end проверка нового Cloudflare аккаунта. На перегруженном X230 тесты новых тяжёлых процессов откладываются.

**Не использовать для аварийного управления оборудованием.** Не передавайте credentials/токены в issue, PR или чат.

© 2026 ARGOS Open Source Contributors · [MIT License](LICENSE).
