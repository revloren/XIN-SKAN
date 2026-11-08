# XIN SKAN

Windows-приложение для исследования цифровых следов Minecraft-читов: существующих файлов, истории файловой системы, свидетельств запуска и связей между ними. Принцип — **Read-Only by Design**: исследуемая система только читается.

## Состояние

Проект на ранней стадии. Готово только то, что перечислено в [docs/PROGRESS.md](docs/PROGRESS.md) с пройденными тестами. Ни один анализатор пока не подключён; приложение ещё ничего не проверяет.

| Этап | Состояние |
| --- | --- |
| Проверка сторонних разборщиков | Готово — [docs/LIBRARY_REVIEW.md](docs/LIBRARY_REVIEW.md) |
| 1. Core и модели | Готово |
| 2. Read-Only Security | Готово — [docs/SECURITY.md](docs/SECURITY.md) |
| 3. Storage (SQLite) | Готово — [docs/STORAGE.md](docs/STORAGE.md) |
| Каркас интерфейса | Готово (показывает только настоящие данные) |
| 4. File Hunter | Не начат |
| 5. History Engine | Не начат |
| 6. Execution Engine | Не начат |
| 7. Evidence Correlation | Не начат |

## Структура

```
src/XINSkan.Models   схема Evidence v1 (без зависимостей)
src/XINSkan.Core     конвейер проверки, разрешения и согласия, нормализация путей
src/XINSkan.Platform.Windows  единственная сборка с системными вызовами; только чтение
src/XINSkan.Security          единственный писатель (папка проверки), аудит, манифест
src/XINSkan.Storage           база SQLite проверки, записи только добавляются
src/XINSkan.App               интерфейс WPF (каркас; показывает только настоящие данные)
tests/               модульные тесты (xUnit)
tools/               инструменты разработки, не входят в поставку
docs/                документация
```

## Сборка

См. [docs/BUILD.md](docs/BUILD.md). Кратко: .NET 10 SDK, затем `dotnet test XINSkan.slnx`.

## Документация

- [docs/EVIDENCE_SCHEMA.md](docs/EVIDENCE_SCHEMA.md) — схема свидетельства и её правила
- [docs/SECURITY.md](docs/SECURITY.md) — как устроен и проверяется Read-Only
- [docs/STORAGE.md](docs/STORAGE.md) — хранилище проверки
- [docs/LIBRARY_REVIEW.md](docs/LIBRARY_REVIEW.md) — проверка библиотек MFT, Prefetch, Jump Lists
- [docs/PROGRESS.md](docs/PROGRESS.md) — отчёты по этапам
