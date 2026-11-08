# Сборка и тесты

## Требования

- .NET 10 SDK (`global.json`: 10.0.100 и новее в линейке 10.0).
- Доступ к nuget.org для восстановления пакетов.
- Windows 10 22H2 или Windows 11 x64 для платформенных модулей и интеграционных тестов (появятся на этапе 2).

## Команды

```
dotnet restore XINSkan.slnx
dotnet build XINSkan.slnx -c Release
dotnet test XINSkan.slnx -c Release
```

Сборка считает предупреждения ошибками и включает рекомендованный набор анализаторов .NET.

## CI

`.github/workflows/ci.yml`:

- **Build and test (Windows)** — сборка и все тесты на `windows-latest`; результаты в артефакте `test-results-windows`.
- **Published parser versions** — информационная проверка, какие версии MFT, Prefetch, JumpList и их зависимостей опубликованы на nuget.org (открытый вопрос из `docs/LIBRARY_REVIEW.md`).

## Без доступа к NuGet

`tools/offline-tests` собирает те же исходники тестов с минимальной заменой xUnit и запускает их без NuGet. Это только для быстрой проверки в изолированной среде; источник истины — CI.

```
dotnet build tools/offline-tests/OfflineTests.csproj -p:XinOffline=true
dotnet tools/offline-tests/bin/Debug/net10.0/XINSkan.UnitTests.dll
```
