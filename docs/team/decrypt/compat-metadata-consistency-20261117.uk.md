# Узгодженість SDK/SPL: передача decrypt до audit/core

Дата: 17 листопада 2026 року, Europe/Berlin.
Задача: `decrypt-compat-alias-001`.
Production snapshot: `e7180783094c803644a54f516edeeb9a8849b7dc`.
База задачі decrypt: `01822442d153c58571c4b4dc8e0811c30996fc28`.

## Результат і межі

Реалізовано вузьке відхилення суперечливих SDK і system security patch level
між public build properties та OTA metadata. Перевірено офлайн на Arch.
Ця задача не запускала телефон, автентифікацію, mount/unmount, flash,
форматування, backup/restore чи Codex.

Профілі, їхні pins, `android_transitions.QUALIFIED_TRANSITIONS`, schema звіту
та `preserve_allowed=false` не змінені. Апаратно кваліфікованих переходів
Android у каталозі залишається **0**. Цей fix сам по собі не дозволяє
встановлювати іншу Android-збірку зі збереженням даних.

## Діагноз → причина → доказ

На базі задачі `_build()` обирав `ro.build.version.sdk` та
`ro.build.version.security_patch` через `or`, ігноруючи одночасно присутні,
але суперечливі `post-sdk-level` та `post-security-patch-level`.
Окремий downgrade-check міг помилково мати `supported`; загальний звіт
лишався `unknown`, а дозвіл запису — `false`.

| Синтетичний вхід | До fix | Після fix |
| --- | --- | --- |
| Source SDK 36; target property 36, OTA post SDK 35 | ANDROID_DOWNGRADE: supported, ніби 36 → 36 | AMBIGUOUS_METADATA, CLI exit 2 |
| Source SPL 2026-11-05; target property 2026-11-05, OTA post SPL 2026-10-05 | SECURITY_PATCH: supported, ніби SPL незмінний | AMBIGUOUS_METADATA, CLI exit 2 |
| Обидва aliases мають однакові значення | Порівняння заявлених фактів | Та сама поведінка; preserve false |
| Є лише property або лише OTA alias | Порівняння доступного значення | Та сама поведінка; preserve false |
| Дані відсутні або обидва aliases порожні | unknown | unknown |
| Один alias порожній, другий заповнений | Міг бути непомітно обраний заповнений | AMBIGUOUS_METADATA |
| System, vendor і boot SPL різні | Незалежні перевірки | Незалежні перевірки збережено |

Первинний baseline:
`$HOME/mcp-work/a22x-recovery-team/roles/decrypt/out/compat-alias-baseline-20261117.json`.
Це фактичний запуск старого коду до редагування, а не очікування нового тесту.

Узгодженість двох пар полів обґрунтовано первинним AOSP-кодом:
[ota_utils.py, commit 4dba876f416278f015a07b8a304c02c5269867dc](https://android.googlesource.com/platform/build/+/4dba876f416278f015a07b8a304c02c5269867dc/tools/releasetools/ota_utils.py).
`UpdateDeviceState()` бере SDK/SPL з відповідних global build properties,
а `BuildLegacyOtaMetadata()` записує їх у OTA post fields.
Перевірено 17.11.2026. Відхилення суперечливого input — політика цього
аналізатора. Fingerprint, pre-device, vendor SPL і boot SPL цим правилом
не прирівнюються до інших полів.

## Що змінено

- `android_compat.py`: 9 рядків перевірки у `_build()` до вибору значень.
  Перевіряється саме присутність ключів, включно з явно порожнім значенням.
  У помилці використано вже наявний `AMBIGUOUS_METADATA`; `details.keys`
  називає два поля. Немає нового check ID чи зміни формату успішного звіту.
- `tests/test_android_compat.py`: 8 нових тестових методів; 18 явних
  subtest cases і 3 окремі сценарії.
- Цей документ: матриця підтримки та сценарій передачі core.

Guard охоплює public source snapshot, package та об'єднання package з
detached target snapshot. Він не доводить, що sidecar build.prop відповідає
байтам system.img. Це окремий невирішений контракт extraction/image binding.

## Офлайн-перевірки і докази

1. **38 analyzer tests PASS**: 30 попередніх і 8 нових. Перевірені SDK/SPL
   конфлікти в обох напрямках, source snapshot, package/target snapshot merge,
   порожні поля, однакові/одиничні aliases, відсутні дані, незалежні vendor/boot
   SPL та CLI exit 2 JSON. Негативний шлях перевірено з забороною викликів
   mount, unmount, reset, flash і rollback writer.
2. Окремий `compat-check` на незмінній базі перевірив **13 profile/selection
   tests PASS** та **13 відхилених підмін pins**. Байти шести файлів звірені з
   `git show 01822442...` перед тестами.
3. `git diff --check` та `teamctl check decrypt --task decrypt-compat-alias-001`
   пройшли для code/tests diff; кінцева перевірка з документом записується
   у receipt передачі.
4. Окремий CLI-набір із шести збережених fixtures перевіряє саме зовнішній
   процес `analyze-files`. Його результат і hashes знаходяться поряд із
   пакетами в `out/compat-alias-qualification-20261117/`.

Корінь доказів:
`$HOME/mcp-work/a22x-recovery-team/roles/decrypt/out/`.

| Файл | Призначення |
| --- | --- |
| compat-alias-baseline-20261117.json | Фактична поведінка бази до fix |
| compat-alias-writer-tests-20261117.log | 38 analyzer tests |
| compat-alias-writer-receipt-20261117.json | Точна команда, hashes code/tests та code diff |
| compat-alias-writer-scope-20261117.json | Перевірка меж writer |
| decrypt-profile-review-001/tests.log | 13 profile/selection tests |
| decrypt-profile-review-001/profile-review.json | Pins, негативні випадки, межі профілів |
| compat-alias-qualification-20261117/expected.json | 6 CLI cases, hashes fixtures і analyzer |
| compat-alias-qualification-20261117/host-result.json | Фактичний запуск CLI cases на Arch |
| compat-alias-qualification-20261117/verify-fixtures.py | Read-only runner для core |
| compat-alias-handoff-20261117.json | Повний фінальний SHA та передача audit/core |

Усі записи й тести виконуються через `teamctl run`. Кеші Python вимкнені;
тимчасові fixture files направлені у власний `out/`.

## Матриця підтримки: різні рівні доказів

Нижче розділено те, що дозволено кодом, попередні записи про hardware та
перевірки цієї задачі. Runtime bundle, firmware bytes і старі апаратні receipts
ця задача не перечитувала; їхні результати не є новим live PASS.

| Профіль/сценарій | Код та pins | Наявний запис про кваліфікацію | Висновок цієї задачі |
| --- | --- | --- | --- |
| Samsung A13: samsung-a226b-a13, user 0 | Exact JAR pair; password/pattern | Базовий password: 2 fresh boots; shared persistent runtime, pattern і Unicode password: PENDING | JSON/code consistency і негативні pins PASS; універсальний pattern/Unicode/RW не підтверджені |
| EvolutionX A16: evolutionx-a226b-a16, user 0 | Exact JAR pair і Gatekeeper namespace; none/password | CE RW scope — тільки password; окремий create/fsync → fresh read/delete/fsync → fresh RO absence record | NONE decrypt admission не є NONE RW qualification; нові hardware claims не додаються |
| EvolutionX password reusable session | Exact session helper у профілі | [Попередня матриця image05](../../reusable-ce-session-20261117.uk.md) описує повторні RO/RW mount без reboot і policy tests | Це попередній звіт про exact образ; поточний стан телефона не перевірявся |
| Інша GSI/нова Android-збірка | Немає загального дозволу за назвою ROM чи SDK | Потрібні exact artifacts і окремі докази | Неперевірена збірка не додається до підтримки |
| A → B зі збереженням даних | Порожній QUALIFIED_TRANSITIONS | Жодної кваліфікованої пари | preserve_allowed=false |

Джерела матриці: `android_profiles.py`, обидва
`profiles/android-decrypt/*.json`, `android_transitions.py`,
попередні профільні документи та незалежний offline profile-review.
Значення `read_only:true` базового профілю не замінює окремий CE RW admission.

## Точний сценарій перевірки цього fix для core

Це сценарій для власника телефона. Роль decrypt його не виконувала.

1. Audit перевіряє точний фінальний commit і власні первинні докази; receipt
   `approved` створює роль audit у своєму `out/`. Core інтегрує тільки
   production-коміт, без службового role-guide `01822442`.
2. Перед апаратною перевіркою core завершує передачу від попередніх сесій,
   фіксує boot ID, образ і installed source pins. Цей offline patch не є
   причиною переривати чужу live-операцію.
3. Core переносить **каталог fixture-набору**, а не кодовий overlay, у
   власний тимчасовий каталог телефона, наприклад
   `/tmp/decrypt-compat-alias-001/`. `system.img` усередині ZIP — лише
   синтетичні 8192 байти з ext4 magic для parser; це не Android-образ,
   його не можна подавати до installer/flash.
4. Core визначає фактичний каталог установленого backend з pins образу і
   запускає з нього перевірений analyzer через runner. Runner вимагає
   `--module-dir`, звіряє SHA android_compat.py та всіх fixture files і
   запускає тільки `analyze-files`; при іншому SHA зупиняється.
   Шаблон команди (шлях backend core підставляє за фактом):

   `python3 -B /tmp/decrypt-compat-alias-001/verify-fixtures.py --module-dir VERIFIED_BACKEND_DIRECTORY`

5. Очікування: `sdk-conflict`, `spl-conflict` та `empty-alias` —
   exit 2 і `ok:false/error.code=AMBIGUOUS_METADATA`; `agreeing` та
   `ota-only` — exit 0, окремі downgrade checks supported, загальний
   unknown, preserve false; `missing` — exit 0 та обидва checks unknown.
   Runner повертає exit 0 тільки коли всі 6 cases відповідають очікуванням.
6. Core записує stdout, exit codes, exact module/image identity та фактичні
   state checks до/після; для цього smoke не потрібні credential,
   mount/unmount чи запис у userdata. PASS цього сценарію підтверджує
   поведінку parser/CLI на телефоні, а не перехід Android A → B.

## Окрема кваліфікація першої пари Android

Для майбутнього A → B потрібні дані, яких ця задача не створює. Конкретний
target B тут не обраний. Першою кандидатною парою може бути лише точна поточна
EvolutionX A → конкретна наступна збірка тієї самої гілки, якщо вона справді
потребує тільки system і не вимагає зміни BOOT/vendor/AVB чи LP resize.

До запису core та власники залежностей мають зафіксувати:
content hashes A/B; extraction receipt з image hash до JAR/build.prop/fstab;
незмінну runtime/TEE/AVB базу навіть для відсутніх у ZIP розділів; user 0,
credential/data epoch і закриті конфліктні сесії; повну перевірену зовнішню
rollback-копію та визначений шлях відновлення після переривання writer.

Мінімальна фізична матриця для цієї конкретної пари:

| Етап | Потрібний доказ |
| --- | --- |
| Android A до переходу | Контрольні файли, вибраний app state і Android Keystore sentinel доступні; source identity/epoch зафіксовані |
| Після запису B, до першого Android boot | Повний readback; свіже recovery; правильний exact target decrypt profile; ті самі CE-контрольні файли читаються |
| Перший Android B boot/unlock | Контрольні файли, погоджений app state і попередній Keystore sentinel працюють |
| Повернення у recovery після B | Decrypt актуального стану, читання й окремо контрольований RW/cleanup у погодженому scope |

Невідомий або failed крок залишає пару некваліфікованою. B → A, інші
користувачі, інші credentials, інші модулі й збереження всіх app schemas
не успадковують PASS A → B. Повернення старого system.img після першого B boot
не є доказом rollback secure state або app migrations.

## Передача та залишок роботи

Власний code/tests patch завершений. Окремий Chat reviewer перевіряє незмінний
SHA; його висновок не замінює інтеграційний receipt ролі audit.
Фінальний SHA, scope check, докази та pending audit/core steps зберігаються в
`compat-alias-handoff-20261117.json` і task status. Телефонні дії залишаються core.
