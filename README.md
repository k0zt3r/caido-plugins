# Caido plugins

Коллекция плагинов для [Caido](https://caido.io/). Каждый плагин находится в отдельной папке внутри `plugins/` и собирается независимо.

## Плагины

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
└── sqlmap-manager/   # отдельный SQLmap-плагин
```

Новые плагины добавляются в `plugins/<plugin-name>/` со своим `manifest.json`, исходниками, README и скриптом сборки.
