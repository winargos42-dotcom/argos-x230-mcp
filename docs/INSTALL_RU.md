# Установка ARGOS X230 MCP (Linux)

Цель: дать обычному пользователю собственный MCP-сервер для разработки и диагностики без использования чужой квоты Desktop Commander.

## Требования

Linux (Arch/Debian/Ubuntu), Python 3.11+, современный браузер; git, bubblewrap (bwrap), systemd и cloudflared нужны соответственно для Git/песочницы/служб/туннеля. Запускайте MCP **от отдельного непривилегированного пользователя**. В CI и учебных тестах допустим текущий пользователь, но не root для production.

## Локальный сервер

```bash
git clone https://github.com/winargos42-dotcom/argos-x230-mcp.git
cd argos-x230-mcp
python3 -m venv .venv
.venv/bin/python -m pip install -e .
mkdir -p "$HOME/.config/argos-x230-mcp" "$HOME/argos-mcp-workspace"
chmod 700 "$HOME/.config/argos-x230-mcp" "$HOME/argos-mcp-workspace"
.venv/bin/python -c 'import secrets,pathlib; p=pathlib.Path.home()/".config/argos-x230-mcp/token"; p.write_text(secrets.token_urlsafe(48)); p.chmod(0o600); print("Token ready")'
.venv/bin/python -m uvicorn argos_x230_mcp.server:app --host 127.0.0.1 --port 8765
```

Не передавайте токен в чат. Проверьте в другом терминале:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8765/mcp
# Ожидаемый HTTP 401 (без авторизации).
```

`ARGOS_MCP_TOKEN_FILE` — путь к локальному токену. `ARGOS_MCP_WORKSPACE` — путь к выделенной рабочей папке. `ARGOS_MCP_PORT` — порт; для запуска через uvicorn нужен тот же порт в параметре `--port`. Не указывайте корень диска в качестве workspace.

## Служба systemd

Сначала убедитесь, что всё работает без systemd. Затем оформите unit, заменив пути и пользователя: пример [deploy/argos-x230-mcp.service.example](../deploy/argos-x230-mcp.service.example). Рекомендуем `MemoryMax`, `CPUQuota`, `NoNewPrivileges`, `ProtectSystem=strict`, запрет лишней записи и доступ только к workspace и файлу токена.

**Не выполняйте MCP от root:** компрометация агента в противном случае даст доступ к системе.

## Песочница Python

`python_project_test` запускает только `unittest discover` в `bubblewrap`. Внутри нет сети, токенов пользователя, доступа к корню рабочего диска; есть лимиты времени, RAM и размера вывода. На Linux с запретом user namespaces запуск может отказать — это ожидаемая защитная реакция; не следует отключать ограничения ядра ради одного теста.

Контроллер `resource_status` показывает запас памяти и температуру CPU. При опасной нагрузке `python_project_test` возвращает отложенный статус 75 до старта песочницы. Он не завершает уже запущенные приложения.

## Подключение через Cloudflare

Читайте [браузерный мастер](BROWSER_TUNNEL_RU.md). Установите `cloudflared` и выполните:

```bash
.venv/bin/argos-mcp-tunnel-wizard
```

При настройке MCP-сервера **отдельно** добавьте в приватные переменные окружения службы:

```ini
ARGOS_MCP_PUBLIC_HOSTNAME=mcp.example.com
ARGOS_CF_ACCESS_TEAM=your-team.cloudflareaccess.com
ARGOS_CF_ACCESS_AUD=access-app-audience-tag
ARGOS_CF_ACCESS_EMAIL=allowed-user@example.com
```

Мастер создаёт туннель и DNS, но не знает вашего Access Audience Tag и не вправе подставлять реальные значения за вас. Сначала создайте Cloudflare Access Self-hosted приложение, затем заполните параметры. Авторизуйтесь в ChatGPT через поддерживаемый маршрут OAuth/Access; совместимость авторизации проверяйте на своём клиенте. Просто внешний HTTPS адрес ещё не доказывает работоспособную авторизацию MCP.

## Обновление и восстановление

Применяйте код сначала в тестовой папке. Делайте git commit перед изменениями, сохраняйте конфигурации в приватной директории. Туннель-мастер **не изменяет** общую конфигурацию системы и старые туннели. Чтобы остановить новый созданный user-service:

```bash
systemctl --user disable --now argos-x230-mcp-tunnel-ИМЯ.service
```

Удаление DNS и tunnel из панели Cloudflare — отдельные действия пользователя (мастер не удаляет облачные ресурсы без явного согласия).
