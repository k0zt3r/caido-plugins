<div align="center">

# Caido Plugins

**Инструменты для анализа JavaScript и работы с sqlmap прямо в Caido.**

[JS Analyzer Plus](plugins/js-analyzer-plus/README.md) · [SQLmap Manager](plugins/sqlmap-manager/README.md)

</div>

---

Два самостоятельных плагина: каждый устанавливается и собирается отдельно.

| Плагин | Для чего | Как запускается |
| :--- | :--- | :--- |
| **[JS Analyzer Plus](plugins/js-analyzer-plus/README.md)** | Маршруты, API endpoints, секреты, захардкоженные login/password и cookies | Пассивно на трафике или вручную по выбранным ответам |
| **[SQLmap Manager](plugins/sqlmap-manager/README.md)** | Запуск sqlmap, очередь задач, живой журнал и результаты в Findings | Вручную, после выбора запроса и нажатия кнопки запуска |

## 🔎 JS Analyzer Plus

Открываешь сайт через Caido — плагин анализирует JavaScript и сохраняет основные находки. Маршруты и API endpoints приходят списками, связанные логин и пароль — одной записью с фактическими значениями.

- AST-анализ на Acorn и 12 regex-анализаторов.
- Вложенные маршруты, Angular hash routes, конфигурации React/Vue/Nuxt и регистрации Next.js Pages Router.
- Отбор автоматических Findings: высокая энтропия и общие эвристики остаются в полном анализе.
- Ручной скан **не отправляет все результаты в Findings** — публикация выполняется отдельным действием.
- Просмотр исходного ответа, подсветка, копирование и экспорт JSON/CSV.

**[Установка, примеры Findings и сборка →](plugins/js-analyzer-plus/README.md)**

## 🛠 SQLmap Manager

Выбираешь запрос в Caido, отправляешь его в SQLmap Manager и запускаешь проверку. Плагин показывает очередь, состояние процесса и журнал, а после распознавания итоговых результатов создаёт Findings.

- Запуск по выбранному запросу и параметрам.
- Очередь, ограничение параллельных задач, остановка и таймаут.
- Поддержка установленного sqlmap и запуска через Python.
- Работа с кандидатами из Findings текущего проекта.
- Установка и открытие страницы сами по себе не запускают сканирование.

**[Настройка, управление задачами и сборка →](plugins/sqlmap-manager/README.md)**

## Установка

Собери нужный плагин по его инструкции и импортируй `dist/plugin_package.zip` через **Plugins → Install** в Caido.

| Плагин | Команды из корня репозитория | Результат |
| :--- | :--- | :--- |
| JS Analyzer Plus | `cd plugins/js-analyzer-plus` → `pnpm install --frozen-lockfile` → `pnpm build` | `plugins/js-analyzer-plus/dist/plugin_package.zip` |
| SQLmap Manager | `cd plugins/sqlmap-manager` → `python3 build.py` | `plugins/sqlmap-manager/dist/plugin_package.zip` |

Для сборки JS Analyzer Plus нужны Node.js, pnpm и Python 3. Для упаковки SQLmap Manager достаточно Python 3; для работы плагина sqlmap должен быть доступен на машине backend Caido.

## Структура репозитория

```text
plugins/
├── js-analyzer-plus/   # анализ JS, просмотр ответов и Findings
└── sqlmap-manager/     # запуск sqlmap и управление задачами
```

Новые плагины размещаются в `plugins/<название>/` со своими исходниками, README и способом сборки.
