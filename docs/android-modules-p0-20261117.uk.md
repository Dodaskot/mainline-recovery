# Android module rescue P0 — реалізація та межі доказів

Дата: 17 листопада 2026 року (Europe/Berlin).
База: `068e070`, план `android-preserve-data-and-modules-20261117.uk.md`.

## Що реалізовано

`android_modules.py` додає read-only інвентаризацію та окрему операцію marker rescue.
Режим використовує наявний Files mount lifecycle, `PinnedVolume`, `operation_lock`
і `file_archive.pack`; іншого writer, ZIP engine чи механізму authentication немає.

- Список активних і pending модулів із ID, назвою, версією та disable/remove/update станами.
- Preview зі стабільним SHA-256 плану, актуальною userdata/session identity, повним BOOT hash,
  framework assets та хешами вмісту вибраних модулів.
- Disable, enable, deferred remove, cancel-remove та disable-all. Pending копії
  перевіряються й змінюються разом з активною версією, а pending-only модулі також включаються.
- Окремий backup active або pending копії модуля через існуючий archive engine на інший носій.
  Архів включає module files і marker state. Це не обіцянка автоматичного Android rollback.
- Apply перевіряє той самий план заново, вимагає явне підтвердження та authenticated RW mount.

Device mode приймає лише `userdata` з live Files receipt: `ce_authenticated=true`,
`fscrypt_policy_verified=true`, `android_user_id=0`, `mount_owner=android-decrypt`.
Заблоковані дані дають зрозумілу діагностику без спроб mount/authentication.
Fixture mode використовує окремі тимчасові каталоги й не є альтернативним admission для телефона.

## Точна область підтримки framework

Початкові marker adapters: офіційний **Magisk 31.0 і 31.1 для arm64**. Detector
порівнює native Magisk у BOOT, `init` у BOOT, встановлений `/data/adb/magisk/magisk`
та `util_functions.sh` із перевіреними release asset SHA-256. Назва папки чи
рядок версії окремо не відкривають записи. BOOT та userdata assets мають відповідати
одній версії. Нічого з userdata або BOOT не виконується як програма.

| Версія | Офіційний APK SHA-256 | arm64 Magisk SHA-256 |
| --- | --- | --- |
| 31.0 | `2c8a488b9a5293e578e95ae4f07e3c57aba4feec4a52ca4dd852a2692d6dd4e8` | `44eece7e1faefe3156c289c74b9f747e0d5b029aed84cbeb85be0139fb03d813` |
| 31.1 | `89cefac0a318afa39fb3880c45c87b036c05bc1ebf02a7a715b7f8d7c26ac6e7` | `fb0ba1b1f3472d34b8ae21edd3a69c2a44f46a3a7c34e85e37c6b2b57d22b9ec` |

Hashes звірено з GitHub release `digest` та файлами всередині відповідних APK.
`native/src/core/module.rs` у двох тегах перевірено: pending replacement переноситься
до active; попередній disable зберігається; remove перевіряється до disable.
Тому remove ставиться в обидві копії, а enable не скасовує deferred removal.

APatch/KernelSU визначаються як кандидати за artifacts і залишаються read-only.
Їхня точна userspace version та узгоджений adapter поки не реалізовані. KernelPatch
version не підміняє версію APatch. Кілька framework directories або невідомі binaries
дають unknown, навіть коли одна папка може бути історичним залишком. Forks і debug
builds не прирівнюються до офіційного релізу.

## Early effects та межа disable-all

Модулі з `sepolicy.rule`, `preinit` або `initrc` доступні read-only: зміна лише
disable-marker не доводить скасування раніше підготовленої early policy. Якщо хоч
один вибраний модуль потребує іншого adapter, disable-all блокується до будь-якого
marker write. Orphan update marker без pending copy також блокується.

Навіть для підтримуваних модулів scope — active/pending markers для наступного
Android boot. Глобальні `/data/adb/post-fs-data.d` і `service.d`, раніші постійні
зміни й попередній secure state автоматично не скасовуються. `uninstall.sh` та
`action.sh` у recovery не виконуються. Після deferred remove `uninstall.sh` може
виконати штатний Magisk на наступному Android boot; preview це явно повідомляє.

## Журнал і помилки

Журнали зберігаються у приватному `/data/adb/a22x-recovery-module-rescue`, окремо
від module directories. Це заявлений додатковий запис у userdata, а не image-writer
доступ. Журнал містить план, попередні й бажані marker states, completed steps
та наступну можливу операцію. Кожен файл і directory fsync перевіряються.

При I/O error чи зміні state результат — `MODULE_TRANSACTION_INCOMPLETE` та
`partial-or-uncertain`. Система не повідомляє success, не повторює запис автоматично
й не оголошує atomic rollback. Після power loss або такого результату потрібно
перечитати журнал та поточний inventory, перш ніж вибрати нову дію. Обмеження —
128 journal entries; автоматичного видалення старих доказів немає.

На початку `apply` виконується повторний повний preview з fingerprint вибраних
module payloads, BOOT/framework і поточного mount/session state. Зміну, помітну
на цій перевірці, відхиляє `MODULE_PLAN_CHANGED` ще до marker write.
Між останнім повним recheck і marker write штатні helpers покладаються на
спільний `operation_lock`: це **cooperative lease**, а не security boundary
проти стороннього root-writer, який ігнорує lock. У незалежному синтетичному
тесті такий writer змінив існуючий `service.sh` in-place після recheck без
зміни directory stamp; `_change_marker` повторно перевірив directory/marker,
але не повний fingerprint payload, і marker operation завершилася `applied`.
Атомарність проти довільного конкурентного запису цим не доведена.
Production failure, втрата даних чи апаратний наслідок не підтверджені.

Symlink traversal, hard-linked metadata, special files, невідповідний module ID,
інший BOOT/framework, RO mount і stale token відхиляються за наявними перевірками.
Звичайні payload symlinks включаються в fingerprint як самі посилання;
їхні цілі не читаються. Підтримуваний Magisk whiteout не відкривається як device.
Обхід одного модуля обмежено 512 MiB, 32768 entries та depth 64.

## CLI та UI contract

```text
android_modules.py --device inventory
android_modules.py --device preview --action disable --module-id example
android_modules.py --device apply --action disable --module-id example --expected-plan SHA256 --confirm
android_modules.py --device preview --action disable-all
android_modules.py --device backup --module-id example --scope active --destination-volume sdcard-p1 --destination /example.tar.zst --confirm
```

`inventory` повертає `framework`, `access`, `modules`, `can_mutate`, `limitations`.
`preview` повертає `plan`, де `allowed`, `reason`, `changes`, `plan_sha256` є
обов'язковими. Apply повторно обчислює SHA; довільний plan file не приймається.
Preview допускається на RO mount, але після переходу до RW потрібний новий preview,
оскільки session/mount identity змінилася. Стандартний JSON error envelope збігається
з filesystem helpers.

## Read-only перегляд журналів (modules-journal-002)

Новий CLI `journals` не створює journal directory, не відновлює та не повторює
marker writes. Він читає лише наявні журнали з authenticated userdata user 0
через Files `PinnedVolume`, той самий operation lock і no-follow/bounded reads.
Список обмежено 128 directory entries, один JSON — 1 MiB. Для device перевіряються
приватний режим 0700 і root ownership каталогу. Некоректні, symlinked і залишкові
`.tmp-*` записи видно як `integrity=invalid`, вони не виконуються й не відкриваються
за межами volume. Відсутній каталог повертає порожній список без запису.

```text
android_modules.py --device journals
android_modules.py --device journals --transaction 0123456789abcdef0123456789abcdef
```

`journals` повертає статус, дію, ID, кількість запланованих і записаних завершених
кроків, SHA-256 journal file та `integrity=self-consistent` лише після перевірки
JSON schema v1, self-hash плану, цілей і послідовності. Це **не підпис** журналу:
скомпрометована userdata може змінити JSON і перерахувати hash. Запит одного
transaction ID додатково читає **поточні** marker states і порівнює з before/desired;
`matches-desired` не доводить, що саме ця транзакція виконала запис, а `applied`
не доводить успішний Android boot. Немає автоматичного reconcile/rollback.
Після partial failure потрібні review journal + свіжі inventory/preview +
окреме явне рішення оператора. Усі 34 unit fixtures PASS, телефон не перевірявся.

## Наступний формат: Magisk module ZIP (лише план P1)

За upstream Magisk 31.1 простий module installer ZIP містить кореневий
`module.prop`, payload і необов'язкові `META-INF/.../update-binary` та
`updater-script` для recovery. `customize.sh` може виконувати довільні команди
або `SKIPUNZIP=1`, legacy `install.sh` змінює сценарій інсталяції. Generic
`zip_install.py` уже відхиляє розпізнані module ZIP через
`MODULE_ZIP_UNSUPPORTED`; цей guard **не прибирати** до окремої кваліфікації.

Пропонований перший P1 scope: ZIP із кореневим коректним `module.prop`, без
legacy/custom install scripts, сувора read-only ZIP inspection (size/path/duplicates/
specials), попередній SHA-256 та контроль цільового installed framework 31.0/31.1.
Встановлення в `/data/adb/modules_update/<id>` потребує окремої транзакції,
резервної копії існуючого модуля, label/ownership, fsync, rollback journal та
кваліфікації boot behavior. Це **ще не реалізовано**. Для `core` потрібен
узгоджений маршрут module ZIP замість generic updater; для `ui` — окремий preview
з явним переліком непідтримуваних scripts. APatch/KernelSU залишаються read-only.

## Докази на 17.11.2026

- Host fixtures: 28 targeted tests — звичайні marker transitions, pending updates,
  stale plan/content/BOOT, RO/auth gate, traversal/symlink/hardlink, early policy,
  неповна транзакція, архівування та bounded BOOT payload extraction.
- Root-controller read-only probe `recovery-p0-boot-version-20261117-27`:
  поточний BOOT `b16d551fbb23e8cf277c0a9cdc7e1a4fa7abf2b30e5d584911046dc451c27228`
  має Magisk payload `fb0ba1b1f3472d34b8ae21edd3a69c2a44f46a3a7c34e85e37c6b2b57d22b9ec`
  та init `c0c7cc1c8e1afb92bff602164f6aa1bb4103f5028d076216d8bef48496e2f4dc`.
  Це збігається з офіційним **31.1**, userdata лишилася unmounted.
- `/data/adb` assets, installed module inventory, actual marker writes,
  unmount/remount durability та наступний Android boot **ще не кваліфіковані**.
  `hardware_qualified=false` у backend не приховується.
- Магіск ZIP installation P1 цим комітом не реалізується. `zip_install.py` не змінений.

## Generic ZIP: виправлений guard перед виконанням

Окремий аудит 17.11.2026 підтвердив, що старий generic ZIP runner лише показував
warning для `module.prop`, але міг виконати його updater і повернути success без
встановленого модуля. Це було відтворено нешкідливим temporary fixture без телефона.

Тепер `inspect` і `run` окремо відхиляють module ZIP через
`MODULE_ZIP_UNSUPPORTED` до target/offline checks, зміни mappings, BOOT backup,
створення Room або запуску updater. Наявність `module.prop` достатня навіть без
`name`; metadata обмежено 32 KiB. `describe` вказує `run_supported=false` і не
перелічує writable/logical targets для такого пакета. Штатна UI error path не
додає відхилений ZIP до черги.

`inspect` може, як раніше, відкрити **лише носій джерела** read-only для читання
пакета. `run` використовує вже переглянуте змонтоване джерело; якщо воно було
відмонтоване, потрібний новий preview, без прихованого remount на write path.
Звичайний kernel/ROM `inspect → run`, включно з початково відмонтованим джерелом,
покрито fixture regression. Відмова module ZIP не виконує mount/unmount,
backup/Room/target writes або updater у протестованому mounted-source випадку.
Це guard для розпізнаного module package; generic ZIP не стає універсальним
ізолятором довільного коду чи кваліфікованим P1 installer.

Перевірка: усі 42 тести `test_zip_install.py` PASS (6.624 s), включно з kernel/ROM
inspect→run та відсутністю updater/backup/Room/target/mount actions на відмові.

## Первинні джерела

- [Magisk module guide](https://topjohnwu.github.io/Magisk/guides.html)
- [Magisk 31.0 release](https://github.com/topjohnwu/Magisk/releases/tag/v31.0)
- [Magisk 31.1 release](https://github.com/topjohnwu/Magisk/releases/tag/v31.1)
- [Magisk 31.0 module implementation](https://github.com/topjohnwu/Magisk/blob/v31.0/native/src/core/module.rs)
- [Magisk 31.1 module implementation](https://github.com/topjohnwu/Magisk/blob/v31.1/native/src/core/module.rs)
- [Magisk 31.1 preinit policy handling](https://github.com/topjohnwu/Magisk/blob/v31.1/scripts/util_functions.sh)
- [APatch module guide](https://apatch.dev/apm-guide.html)
- [KernelSU module guide](https://kernelsu.org/guide/module.html)
