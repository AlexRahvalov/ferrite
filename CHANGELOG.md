# Changelog

Что изменено, в хронологическом порядке (новое сверху).
Планы: `ROADMAP.md`. Правила: `AGENTS.md`.
Каждая запись: коммит, что сделано, чем подтверждено.

## pre-configuration: документация проекта и контрольные теги

Добавлены `ROADMAP.md` и `CHANGELOG.md`, в `AGENTS.md` добавлен раздел
о ведении документации. На `132cd94` поставлен тег `stage-1-done`, на этот
коммит поставлен тег `pre-configuration`.
Подтверждено: сверка хэшей коммитов, списка модулей и количества тестов
(`43` теста по workspace), зелёный CI.

## 903962f: Cargo.lock в git и server-data/ в .gitignore

В `.gitignore` добавлен `server-data/`, убран дубль `/purpur-server`,
удалён `Cargo.lock`; сам `Cargo.lock` зафиксирован в репозитории.
Подтверждено: `git grep -i "GitHub - Lab" Cargo.lock` пуст, `git check-ignore -v`
подтверждает игнорирование `recordings/`, `purpur-server/` и `server-data/`,
CI зелёный.

## 3ea43bb: сторож CI расширен на tools/ и #![allow(

В `.github/workflows/ci.yml` шаг `Forbidden patterns` сканирует `crates/`
и `tools/`, а регулярное выражение ловит внутренние атрибуты `#![allow(`.
Подтверждено: два изолированных тестовых PR (`test/ci-guard-crates-inner`,
run `46121555912`, и `test/ci-guard-tools`, run `46121567628`) упали именно
на шаге `Forbidden patterns` на Ubuntu и Windows (PR закрыты без слияния,
ветки удалены); CI на `main` зелёный (run `46121860874`).

## 4356664: экранирование клиентских строк в логах и проверка hex в Uuid::parse_str

- Вывод строк от клиента (`server_address`, `username`) в `session.rs`
  переведён на `format_*` с `{:?}` (проверены все `println!`/`eprintln!`/`format!`
  в `crates/` и `tools/`).
- В `Uuid::parse_str` добавлена проверка `is_ascii_hexdigit()` (находка:
  `u8::from_str_radix` принимал ведущий `+`, разбирая `"+0+1..."` как UUID).
- Добавлены 3 теста (всего в workspace стало 43 теста):
  1. `parse_str_rejects_non_hex_and_plus_prefixed_nibbles` — проверка отказа
     на `+` и не-hex байтах (падал Red до правки).
  2. `client_strings_with_newlines_and_ansi_are_escaped_in_logs` — защита от
     инъекций `\r`, `\n`, ESC, C1 `\u{9b}` и bidi `\u{202e}` в логи (падал
     Red до правки).
  3. `parse_str_multibyte_utf8_exact_uuid_byte_lengths_do_not_panic` — возврат
     `Err` без паники на многобайтовых UTF-8 строках длиной 32 и 36 байт
     (прошёл сразу без Red, так как `as_bytes().get(idx)` не резал строку;
     способность теста падать подтверждена временной мутацией на байтовый срез
     с паникой на индексе `8`).
- Подтверждено: `cargo test --workspace` (43 passed), CI зелёный (run `45999922688`).

## 02aa9e1: ferrite-net разбит на модули

`lib.rs` разделён на `listener`, `framing`, `capture`, `session`.
Только перенос: тела 13 тестов не менялись, новых `pub` нет, расширена
видимость шести внутренних элементов до `pub(crate)`.
Подтверждено: сверка множеств строк до и после, release-сборка без
предупреждений, CI зелёный.

## cda8a35: усиление безопасности ferrite-net

Каждое исправление начиналось с падающего теста.

- Лимит фрейма 4 КиБ до Configuration (раньше аллокация до 2 МиБ
  по 3-байтовому заголовку).
- `write_timeout` и `shutdown()` перед закрытием.
- Цикл `accept` переживает ошибки; пауза 50 мс при повторных ошибках
  (без 100% CPU); `TCP_NODELAY`.
- Обезличивание `c2s_login_start.bin`: валидный UTF-8 той же байтовой
  длины для многобайтовых ников; без паники на битых входах.
- Захват фикстур атомарный (`create_new`), только при `protocol_version`
  777.
- 7 новых тестов, 30 прогонов подряд зелёные.

## b2f97b1: рекордер трафика (этап 2.2)

`tools/ferrite-recorder`: локальный прокси `127.0.0.1:25566` на
`127.0.0.1:25565`, запись фреймов в `recordings/*.rec` (в `.gitignore`),
остановка записи на входе в Play, `--inspect` без содержимого реестров.
Наблюдения (Purpur 26.3, `online-mode=false`, без сжатия):

- `session_id` у сервера: случайный UUID v4, не равный UUID игрока.
- UUID игрока совпал с offline-UUID (v3, MD5 `OfflinePlayer:<ник>`).
- Finish Configuration: 0x03 в обе стороны.
- Порядок и ID пакетов Configuration: таблица в `ROADMAP.md`.
  Часть ID сдвинута на +1 относительно схемы 26.1.

## 6176acb: Login offline (этап 2.1)

Пакеты Login Start (0x00), Login Disconnect, Login Success (0x02),
Login Acknowledged (0x03); offline-UUID; автомат состояний.
Находка: в 26.3 Login Success содержит четвёртое поле `session_id`
(UUID после `properties`). Без него клиент падал с
`DecoderException: login_finished`. Подтверждено ответом клиента
(Login Acknowledged). Фикстуры `c2s_login_start.bin` (обезличена до
записи) и `c2s_login_acknowledged.bin`, записаны сервером.

## 132cd94: фикстуры SLP (этап 1, тег `stage-1-done`)

Реальные пакеты клиента 26.3 (Handshake, Status Request, Ping),
записанные сервером при подключении. Протокол 777 подтверждён клиентом.
Правило 10 в `AGENTS.md`: фикстуры создаются только сервером.
CI зелёный; сторож запрещённых конструкций проверен красным на
тестовой ветке.

## e991609: каркас и Handshake + Status (этап 1)

Workspace из пяти crates (`ferrite-nbt`, `ferrite-protocol`,
`ferrite-net`, `ferrite-world`, `ferrite-server`), кодек (VarInt, строки,
фрейминг), пакеты Handshake/Status/Ping/Pong, SLP JSON, таймаут чтения
и лимит соединений. CI на Ubuntu и Windows, сторож `#[ignore]`,
`#[allow(`, `todo!(`, `unimplemented!(`. `AGENTS.md` с правилами
честности.

## Как вести этот файл

- Новая запись после каждого коммита в `main`, сверху.
- Указывать, чем подтверждено (тест, реальный клиент, CI), а не «работает».
- Неподтверждённое выносить в «открытые вопросы» в `ROADMAP.md`.
- Не вставлять данные реестров и записи трафика.
