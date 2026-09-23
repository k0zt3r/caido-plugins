# Caido plugins

Коллекция плагинов для [Caido](https://caido.io/). Каждый плагин находится в отдельной папке внутри `plugins/` и собирается независимо.

## Плагины

### JS Analyzer Plus

Путь: `plugins/js-analyzer-plus/`. Пассивный анализ JS/JSON-трафика с автоматическим
сохранением кандидатов в Findings и дедупликацией повторных ответов.
При обновлении сохранённая настройка автоскана остаётся прежней; включение через
палитру команд: `JS Analyzer Plus: Toggle automatic passive scan`.
Сборка: `cd plugins/js-analyzer-plus && pnpm install --frozen-lockfile && pnpm build`.
Готовый архив: `plugins/js-analyzer-plus/dist/plugin_package.zip`.
Подробнее: [MERGE-NOTES.md](plugins/js-analyzer-plus/MERGE-NOTES.md).

### SQLmap Manager

Путь: `plugins/sqlmap-manager/`

Плагин запускает sqlmap для выбранных запросов Caido, показывает живой журнал выполнения и создаёт Findings после распознавания результатов. Инструкция по настройке и сборке находится в [README плагина](plugins/sqlmap-manager/README.md).

Сборка ZIP:

```bash
cd plugins/sqlmap-manager
python3 build.py
```

Готовый архив появится в `plugins/sqlmap-manager/dist/plugin_package.zip`.

## Структура

```text
plugins/
├── js-analyzer-plus/ # анализ JS и Findings
└── sqlmap-manager/   # отдельный SQLmap-плагин
```

Новые плагины добавляются в `plugins/<plugin-name>/` со своим `manifest.json`, исходниками, README и скриптом сборки.
