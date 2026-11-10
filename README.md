# XIN SKAN

Windows-приложение для исследования цифровых следов Minecraft-читов: существующих файлов, истории файловой системы, свидетельств запуска и связей между ними. Принцип — **Read-Only by Design**: исследуемая система только читается.

## Состояние

Проект на ранней стадии. Готово только то, что перечислено в [docs/PROGRESS.md](docs/PROGRESS.md) с пройденными тестами. Подключены File Hunter (существующие файлы), History Engine (удалённые, переименованные и открывавшиеся файлы, журнал изменений, Корзина, логи Minecraft, ярлыки, Jump Lists, ShellBags всех пользователей) и Execution Engine (следы запуска: Prefetch, BAM, Amcache, UserAssist, журналы событий). Они собирают факты и отдельные косвенные признаки (Low), но **не делают выводов о нарушении**: корреляция (этап 7) связывает записи одного файла и находит закономерности уровня Low/Medium, база клиентов (этап 9) сопоставляет файлы и моды со списком заказчика, а High возможен только при проверенной идентификации и трёх независимых источниках.

| Этап | Состояние |
| --- | --- |
| Проверка сторонних разборщиков | Готово — [docs/LIBRARY_REVIEW.md](docs/LIBRARY_REVIEW.md) |
| 1. Core и модели | Готово |
| 2. Read-Only Security | Готово — [docs/SECURITY.md](docs/SECURITY.md) |
| 3. Storage (SQLite) | Готово — [docs/STORAGE.md](docs/STORAGE.md) |
| Каркас интерфейса | Готово (показывает только настоящие данные) |
| 4. File Hunter | Готово — [docs/FILE_HUNTER.md](docs/FILE_HUNTER.md) |
| 5. History Engine | Частично — [docs/HISTORY_ENGINE.md](docs/HISTORY_ENGINE.md) (нет теневых копий: ждут решения владельца) |
| 6. Execution Engine | Частично — [docs/EXECUTION_ENGINE.md](docs/EXECUTION_ENGINE.md) (нет SRUM) |
| 7. Evidence Correlation | Частично — [docs/CORRELATION.md](docs/CORRELATION.md) (нет связи по содержимому и отчёта-хронологии) |
| 8. Minecraft Integrity | Частично — [docs/MINECRAFT_INTEGRITY.md](docs/MINECRAFT_INTEGRITY.md) (сверка с локальными файлами версий; с хешами Mojang — ждёт решения владельца) |
| 9. База клиентов и признаков | Частично — [docs/SIGNATURE_DATABASE.md](docs/SIGNATURE_DATABASE.md) (список заказчика, 9 проектов проверены по исходному коду, 57 хешей выпусков, файлы данных клиентов, каталог 97 функций, подписанные обновления) |

## Структура

```
src/XINSkan.Models   схема Evidence v1 (без зависимостей)
src/XINSkan.Core     конвейер проверки, разрешения и согласия, нормализация путей
src/XINSkan.Platform.Windows  единственная сборка с системными вызовами; только чтение
src/XINSkan.Security          единственный писатель (папка проверки), аудит, манифест
src/XINSkan.Storage           база SQLite проверки, записи только добавляются
src/XINSkan.Ntfs              разбор NTFS: записи MFT, цепочки кластеров, USN, карта путей
src/XINSkan.ShellFormats      разбор ярлыков, элементов оболочки, составных файлов, Jump Lists
src/XINSkan.Analyzers.FileHunter  существующие файлы: содержимое, хеши, метаданные, подписи
src/XINSkan.Analyzers.History     MFT, USN, Корзина, логи Minecraft, LNK, Jump Lists, ShellBags
src/XINSkan.ExecutionFormats      разбор Prefetch, XPRESS Huffman, кустов реестра (regf) с журналами
src/XINSkan.Analyzers.Execution   Prefetch, BAM, Amcache, UserAssist, журналы событий, кусты пользователей
src/XINSkan.Analyzers.Minecraft    лаунчеры и экземпляры, сверка клиента и библиотек, параметры JVM
src/XINSkan.Correlation           связь записей одного файла, правила находок, политика уровней
src/XINSkan.Signatures            база клиентов: загрузка, проверка подписи, сопоставление
src/XINSkan.Investigation     одна проверка целиком: папка, аудит, база, анализаторы, манифест
src/XINSkan.Cli               командная строка: xinskan investigate / verify / signatures
src/XINSkan.App               интерфейс WPF (показывает только настоящие данные)
tests/               модульные тесты (xUnit)
database/            база клиентов: список заказчика, проверенные признаки, хеши, манифест
tools/               инструменты разработки (xinskan-db — выпуск и подпись базы), не входят в поставку
docs/                документация
```

## Сборка

См. [docs/BUILD.md](docs/BUILD.md). Кратко: .NET 10 SDK, затем `dotnet test XINSkan.slnx`.

## Документация

- [docs/EVIDENCE_SCHEMA.md](docs/EVIDENCE_SCHEMA.md) — схема свидетельства и её правила
- [docs/SECURITY.md](docs/SECURITY.md) — как устроен и проверяется Read-Only
- [docs/STORAGE.md](docs/STORAGE.md) — хранилище проверки
- [docs/FILE_HUNTER.md](docs/FILE_HUNTER.md) — что File Hunter ищет, записывает и чего не делает
- [docs/HISTORY_ENGINE.md](docs/HISTORY_ENGINE.md) — модули истории, правила интерпретации, пределы
- [docs/LIBRARY_REVIEW.md](docs/LIBRARY_REVIEW.md) — проверка библиотек MFT, Prefetch, Jump Lists
- [docs/EXECUTION_ENGINE.md](docs/EXECUTION_ENGINE.md), [docs/CORRELATION.md](docs/CORRELATION.md), [docs/MINECRAFT_INTEGRITY.md](docs/MINECRAFT_INTEGRITY.md) — следы запуска, корреляция, целостность игры
- [docs/SIGNATURE_DATABASE.md](docs/SIGNATURE_DATABASE.md) — база клиентов, виды совпадений, подписанные обновления
- [docs/PROGRESS.md](docs/PROGRESS.md) — отчёты по этапам
