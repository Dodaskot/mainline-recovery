# Огляд UI: перше виправлення

Основа: commit 988aef4467bdb910b9d29c47d63ec7264f5daeaa, окремий worktree. Daylight: світлі плитки на світлому фоні мали слабку межу. Колір краю поверхні змінено; до і після збережено як локальні рендери домашнього екрана. Інші теми не змінено.

Перевірка: host build та 106 UI self-tests PASS; рендер головного екрана оглянуто. Це не перевірка на телефоні або всіх екранів. На момент першого виправлення підпис каталогу ще обрізався. Нова інтеграція функцій, збірка образу та встановлення не виконувались. Стан телефону не змінювався; контролер телефона належить іншій сесії.

Друге виправлення: підпис каталогу скорочено до «Онлайн-системи» та перекладено п'ятьма підтримуваними мовами. Локальні рендери шести мов зібрано у catalog-six-languages.png; обрізання на цій плитці не видно. UI self-tests 106 PASS, locale-ui-test 30 checks / 312 zones PASS, git diff --check PASS. Спроба неіснуючої цілі locale-ui-integration не запускала тест; виконано фактичну ціль locale-ui-test.

Далі: узгодити доступ до контролера, отримати фактичні знімки доступних екранів, визначити перелік недоліків та функцій і перевірити зміни на пристрої.

## Продовження 17.11.2026

На телефоні після передачі контролю під lock переглянуто RO password cancel, Files, Power, Install/Wipe, Aurora settings та перемикання трьох UI password policies з поверненням each_mount. Журнал, оригінальні framebuffers і межі доказу: `$HOME/a22x-work/artifacts/lk-recovery-bridge-20261114/ui-audit-continuation-20261117/live-20261117/REPORT.uk.md`.

Додано локалізацію RO/RW для de/es/fr/pl і побачені відсутні німецькі повідомлення password/policy/format; результат, який повертає на FILE_VOLUME, тепер має загальний підпис Back. Host UI 106, locale 30/312, nav PASS; німецький policy preview оглянуто. Це не встановлення чи перевірка змін на телефоні.

Після одноразового Cancel порожнього format-password prompt наступне читання framebuffer отримало відмову Recovery busy; результат Cancel не встановлено. Дотримуватися NO_RETRY; реального format, password submit або нового reboot/flash не було.

## Офлайн checkpoint: fixture і формулювання

`file-volume-userdata` — окремий синтетичний locked Android user0/F2FS із невідомим credential до prepare, pending qualification і RO/RW choices. Linux userdata/ext4 у `files` лишився окремим fixture; попередня помилка була лише в preview і не доводить дефекту Linux на пристрої.

`home-daylight-after.png` перегенеровано після скорочення підпису: німецьке «Online-Systeme» вміщується. `android-userdata-daylight-preview.png` і `format-review-aurora-preview.png` — нові локальні рендери, всі три переглянуті. На попередньому review сторінка стверджувала, що нічого ще не стерто, але заголовок списку `ERASED` німецькою читався як `GELÖSCHT`; заголовок замінено на `WILL BE ERASED` / `WIRD GELÖSCHT`. Той самий текст використано для сторінки Android reset request. Це лише UI; токени, epoch та інші backend guards не змінені.

Старий Cancel з VOLUME_CHANGED міг відбутися після завершення TTL, що не встановлює backend regression. Виправлення `Back` описує фактичну сторінку повернення; guard і повідомлення про оновлення стану збережені. Зміни на телефон не встановлювались. Recovery busy/no-retry лишається окремим блокером, його аналізує незалежний reviewer.
