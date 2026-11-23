# Незалежний аудит Android tools P0 та наступного preserve-етапу

Дата: 17.11.2026. Аудитор: окремий чат B за прямою вказівкою власника.
База: `341e4a1915ddb60d512936f2be99112bb5052913`.

## Ролі та рівень доказів

Основний чат A веде поточні фізичні перевірки й залишається єдиним контролером телефона.
Цей аудит не робив phone/ADB/UART/auth/flash дій. Зміни виконані в окремих робочих
деревах і потребують зустрічного review перед інтеграцією основним контролером.
Висновок на основі коду, fixture PASS, ARM64/QEMU PASS та фізичний результат — різні
рівні доказів. PASS перевірки не поширюється на неперевірений наступний етап.

## Підтверджені дефекти і виправлення

| ID | Дефект бази | Виправлення / перевірка |
| --- | --- | --- |
| A1 | Одиничний ZIP `system_ext.img` або `system_dlkm.img` помилково ставав `system`; невідомий raw теж отримував `system`. | Явні, заборонені та slot-suffixed targets зберігаються перед GSI aliases. До зміни 14 regression subcases відтворили помилку; після зміни 30 analyzer tests PASS. Початковий коміт `7bc981f`. |
| M1 | Generic ZIP runner виконував updater стандартного module ZIP попри недоступність P1; `magisk_zip_install_available=false` не був backend guard. | `MODULE_ZIP_UNSUPPORTED` незалежно в inspect і run до target/offline/backup/Room/writer. Наявність root `module.prop`, навіть без display name, є достатньою для відмови. 42 ZIP tests PASS, включно з успішним kernel/ROM inspect→run. Початковий коміт `22b1bcf`. |
| U1 | Один unsupported module directory з неправильним ID відхиляв увесь inventory. | Діагностичний рядок лишається видимим; strict ID guard збережено перед preview/apply; unsupported rows не можуть мати actions. Початковий коміт `aa63236`. |
| U2 | Backend допускає32 images, а UI приймав лише80 checks. | Bound192; реальна32-image ZIP fixture дала130 checks і повністю пройшла C parser/render;193 checks відхиляються. Початковий коміт `aa63236`. |

M1 закриває розпізнаний стандартний module ZIP route. Це не універсальне визначення
довільного updater script і не нова гарантія ізоляції generic ZIP runtime.
Run після відмонтування джерела вимагає нового inspect, без прихованого remount.
Inspect може штатно відкрити лише носій джерела для читання; цільові розділи на
module rejection не монтуються і не записуються.

Додаткове live UI спостереження за вже збереженим кадром основного чату:
`live-ui01/03-modules-locked.png` має англійську причину
`Unlock and mount Android user 0 through Files first.` та сирий `unknown` у німецькій
локалі. Це окреме косметичне уточнення для наступного UI review, не blocker запису.

## Перевірка теорії preserve: що ще не доведено

### 1. Metadata поруч із образом не доводить вміст цього образу

`android_compat.py::_package`, `collect_current` і `analyze_fd` чесно залишають
`runtime_files_bound_to_images=false`. Новий image hash разом із довільними сусідніми
JAR/fstab/build.prop не дає target admission. `android_decrypt.py::select_current_profile`
має конкретні framework pins; назва Evolution16 не замінює exact profile.

Наступний offline результат: extraction receipt конкретного target, який зв'язує
hash декодованого образу, спосіб читання, paths і hashes фактично витягнутих public
компонентів. Не додавати неперевірені JAR hashes до allowed profile за назвою ROM.

### 2. Ідентичність збірки і конкретного preview слід розділити

Snapshot hash зараз містить шлях, device/inode/time identity. Це добре для stale
preview rejection, але повторне витягування однакових байтів дасть іншу identity.
`android_transitions.py` ще не має кваліфікованих переходів.

Потрібні стабільний content manifest образів/runtime і окреме execution binding
до актуального boot/data epoch, geometry, volume token та operation lease.
Registry описує напрям A→B і конкретний vendor/credential/user/module scope;
обернений B→A не успадковує qualification автоматично.

### 3. Незмінні розділи треба перевіряти навіть за їх відсутності в ZIP

`FIXED_FIRST_PAIR` checks зараз будуються для присутніх у write_set images.
Для system-only пакета це не доводить identity фактичних BOOT/vendor/AVB.
Відсутність vendor.img означає лише відсутність запланованого запису vendor.

Profile першої пари має pin незмінної runtime бази, а executor звіряє її незалежно
від складу цільового пакета. Target, якому потрібні інші розділи, не можна штучно
обрізати до system-only заради простого першого тесту.

### 4. Readback не дорівнює crash recovery великого logical write

У `flash.py::save_rollback` розділи понад64MiB повертають None;
`write_logical` викликає цей шлях без pending; `write_logical_content` повертає
`recorded:false`. Наявний small-physical journal тому не є готовою гарантією
відновлення після interruption великого system write.

Зберегти низькорівневий writer, але додати orchestration transaction, прив'язану
до повної перевіреної зовнішньої копії попереднього розділу. Після interruption
recovery має знайти незавершений запис і мати конкретний перевірений шлях його
завершення або restore. Саме збільшення ROLLBACK_LIMIT цього не доводить.

## Найвужчий обґрунтований наступний сценарій

Точний поточний Evolution16 A → конкретна наступна збірка тієї самої GSI-гілки B,
яка справді потребує лише super/system: без LP resize та змін BOOT/vendor/AVB,
credential або user scope. Конкретний target у цьому аудиті не обраний.

1. До запису: A/B content manifests, pinned незмінна runtime база, повна system
   backup із reread, контрольні файли/app state й перевірюваний Android Keystore sentinel.
2. Після запису, до Android B: full readback, fresh recovery, правильний target
   decrypt profile та читання поточних CE даних.
3. Після першого Android B unlock: файли/app state й попередній Keystore sentinel
   працюють; після повернення в recovery decrypt актуального нового стану теж працює.

Лише такий результат кваліфікує цю пару A→B. Він не доводить універсальний перенос
всіх apps, downgrade, B→A або сумісність неперевірених модулів.
`preserve_allowed=false` лишається чинним до завершення потрібних контрактів.

## Зустрічний review

Основний чат має незалежно перевірити commits, оцінити сумісність зі своїми новими
змінами та записати accepted/rejected з конкретним контрприкладом або evidence.
Незгода є відкритим технічним питанням; сам факт двох однакових відповідей не є доказом.
Спільний канал: `session-coordination-20261115-chatgpt/peer-watch-20261117/`.
Файл chat-a.json пише лише чат A; chat-b.json — лише аудитор B. Без ACK не заявляємо
підтверджений взаємний моніторинг. Давній heartbeat означає лише відсутність видимого
прогресу; стан host job і актуальні receipts перевіряються перед висновком.

## Інтегрована перевірка трьох виправлень

Зведений source commit `cd7f4ae1f068318eee53af4acd173dce5c512a1c`:100 backend tests
(analyzer30, modules28, ZIP42) PASS;2 Python→C report boundary tests PASS;
Android-tools contract/async suite PASS; static ARM64 binary зібрано, QEMU106 UI
self-tests PASS. Стан перевірено17.11.2026 14:51UTC. Hardware actions цього чату0.
Повний receipt: `$HOME/a22x-work/artifacts/recovery-independent-audit-20261117/COMBINED-TESTS.json`.

Зведені cherry-pick commits: mapping`7bc981f`, ZIP`1211440`, UI`cd7f4ae`.
Пакет для зустрічного review будується окремо; його збірка не означає встановлення.
