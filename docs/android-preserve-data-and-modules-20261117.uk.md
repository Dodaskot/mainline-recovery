# Android зі збереженням даних та керування модулями

Дата: 17 листопада 2026 року (Europe/Berlin).
Статус: підготовлений технічний план після незалежного read-only review; це дизайн, а не реалізована підтримка.
База огляду: recovery-session-20261117, commit 988aef4467bdb910b9d29c47d63ec7264f5daeaa.
Ціль: Samsung Galaxy A22 5G SM-A226B / a22x / MT6833.

## Рішення

Першим реалізувати явний режим оновлення сумісного Android зі збереженням userdata через наявні native writers. Кваліфікувати конкретну пару поточна збірка → цільова збірка. Не заявляти збереження всіх даних для довільних ROM, downgrade або спільного /data між незалежними Android.

Окремо додати менеджер Android root-модулів, спочатку діагностику та вимкнення несправного модуля, потім встановлення recovery-compatible Magisk ZIP через існуючий installer. Встановлення root і root-модулів — різні можливості.

Перший кандидат для майбутньої кваліфікації: поточний Evolution 16 → сумісна наступна збірка тієї самої гілки з незмінними BOOT/vendor/AVB та узгодженим системним набором. Конкретний target image поки не вибраний і не перевірений; підтримку переходу ще не доведено.

## 1. Фактична база й прогалини

| Компонент | Підтверджено локальним кодом/доказом | Потрібна зміна |
| --- | --- | --- |
| Decrypt | Exact Evolution16/password/user0, session4, повторні RO/RW mounts без reboot, 5 cached mounts без повторного введення, fresh format authorization + cancel | Зберегти цю базу; нові ROM та credential types кваліфікувати окремо |
| android_profiles.py | Дві точні пари services.jar/framework.jar: Samsung13 та Evolution16 | Каталог окремо перевірених current/target profiles, без послаблення identity checks |
| android_decrypt.py::select_current_profile() | Невідома пара JAR hashes дає UNSUPPORTED_PROFILE | Підготувати target profile до встановлення; невідомий профіль не означає пошкодження ключів |
| android_gsi.py::inspect()/install_gsi() | erase userdata/metadata/cache у плані, після image writes викликає sf.android_data() | Окремі policy та executor для preserve |
| samsung_firmware.py::install_firmware() | Після firmware writes викликає android_data() | Аналогічна явна keep-policy; назва HOME_CSC сама не гарантує поведінки |
| install.py::_plan()/execute() | install-stock позначає userdata_written і викликає reset_android() | Той самий контракт у третьому entry point; automatic_factory_reset=false не є гарантією незмінного userdata |
| flash.py | Existing write journal, save_rollback(), restore_copy(), readback | Повторно використати; показати повноту rollback |
| flash.py::check_logical() | Автоматична копія лише до ROLLBACK_LIMIT=64 MiB | Повна rollback-копія великих system/super/logical images має окремо існувати на достатньому носії |
| zip_install.py::describe()/Room | ZIP queue/update-binary/edify/Android runtime існує; module.prop розпізнається, але data-path для модулів закритий | Розширити module branch; не писати другий ZIP engine |
| Root | Magisk/APatch install вже існує | Не дублювати |
| Backup, файлові операції, MTP/ADB/SSH, sideload, terminal, update recovery | Наявні відповідні механізми | Виправляти конкретні прогалини, не копіювати однойменні екрани OrangeFox |

Актуальний апаратний доказ: [reusable-ce-session-20261117.uk.md](reusable-ce-session-20261117.uk.md).
Його scope не охоплює всі ROM, physical UI password submit, реальне форматування або power-loss durability.

Старі ANDROID_DECRYPT_API.md, ui/INSTALL_UI.md та ранні crypto звіти містять історичні обмеження або суперечать новішому коду. Оцінювати поточний executor і завершені receipts, а не один старий опис.

## 2. Межа обіцянки «всі дані збережено»

Збереження байтів userdata, можливість decrypt у recovery та правильна робота старих Android app/system даних у новій ROM — три різні умови.

| Сценарій | Політика |
| --- | --- |
| Підтримуване оновлення тієї самої ROM, узгоджені firmware/signatures/schema | Кандидат на keep-compatible після перевірки конкретної пари |
| Інша GSI на тому самому vendor | Сумісність невідома до профілю переходу та перевірки system data |
| Samsung13 ↔ Evolution16 або незалежні ROM | Не обіцяти збереження всіх app accounts/settings; розглянути вибіркову міграцію |
| Пониження Android/patchlevel | Keep за замовчуванням не допускається без підтвердженого підтримуваного шляху |
| Окремі userdata для різних ROM | Зберігає кожне середовище окремо; не робить app state спільним |
| DSU для пробного GSI | Окремий кандидат лише після перевірки підтримки; DSU має власне userdata й не надає старі встановлені програми автоматично |

Навіть відома та сама ROM-гілка є початковим фільтром, а не достатнім доказом сумісності.

Дані програм залежать від package identity, signing certificate/rotation lineage, appId/UID/sharedUID, SELinux labels, версій системних баз і hardware-backed app keys. Копіювання /data як каталогу не відтворює всі ці відносини. Міграція фото/файлів і підтримуваних app exports реалістичніша за універсальний перенос усіх входів у застосунки.

## 3. Preflight перед будь-яким записом

Окремий Android compatibility component повинен формувати незмінний план для existing writers. Не використовувати install_plan.py як готовий Android planner: він описує Linux distro/shared-home install.

План містить:

- source і target build/device identity, hashes images та всіх dependency profiles;
- узгоджений набір system, system_ext, product, vendor, odm, BOOT/dtbo/vbmeta, якщо пакет їх містить;
- architecture, VINTF/kernel constraints, partition geometry, free space, logical extents;
- filesystem/fstab: F2FS/ext4, fscrypt policy, flags, metadata encryption і dm-default-key options;
- Keymaster/Gatekeeper/vendor runtime, secure firmware identity, namespace, credential schema;
- profile identity для decrypt поточного стану й target стану, credential type/user scope;
- OS/system/vendor/boot patch levels і фактичний AVB/root-of-trust context;
- system package signing identities, appId/sharedUID та відомий підтримуваний migration path;
- поточний/цільовий root framework, його версія, установлені та pending модулі й окремий результат їх сумісності;
- exact write-set, protected-set, джерело install-пакета та rollback coverage;
- поточний boot/data/session context, відсутність конфліктної операції та source-file identity;
- результат кожної перевірки: supported / incompatible / unknown з конкретною причиною.

Підпис/хеш пакета доводить походження/цілісність, але не data compatibility. VINTF PASS також не доводить сумісність Android databases або recovery decrypt.

Якщо firmware/version tuple не підтримується, preserve повертає пояснення до запису. Не переходити автоматично до format, не міняти PIN, не видаляти locksettings/spblob, не міняти fstab для вимкнення encryption, не підміняти patchlevel для маскування несумісності.

## 4. Режими та UX

### Оновити зі збереженням даних

Доступний лише для підтвердженого transition profile. Перед запуском показати target, список розділів для запису, що дані зберігаються, підтримку decrypt до/після й реальні можливості повернення. Якщо бракує одного факту, показати саме його: наприклад, «профіль recovery для цієї збірки ще не перевірено».

Для першого MVP використовувати декларативний image package/native writer. Не обіцяти preserve для довільного update-binary: нинішній ZIP runtime з CAP_SYS_ADMIN не є нездоланною межею, а post-run protected hashes виявляють небажаний запис уже після факту.

### Перенести підтримувані дані до іншої ROM

Окремий майбутній режим міграції, а не перейменована галочка keep. Використовувати наявні file-archive/export інструменти. Явно показувати обсяг: shared files, підтримувані app exports, придатні app data після перевірок. Не копіювати повністю system directories між несумісними ROM і не обіцяти збереження всіх hardware-backed secrets.

### Чисте встановлення

Існуюча окрема дія з чинною fresh format authorization. Невдала preserve операція ніколи не викликає її як fallback.

## 5. Виконання preserve

### Модулі під час оновлення Android

Окремо оцінювати ROM/data compatibility, recovery decrypt, root framework та модулі. Bootloop через старий модуль не є доказом втрати даних або зламаного шифрування. Не переносити старий patched BOOT у новий набір і не патчити цільовий BOOT автоматично. Якщо новий BOOT прибирає активний root, збережені модулі можуть знову активуватися після його майбутнього повернення.

Коли сумісність модулів невідома, план може запропонувати явний перший запуск із вимкненими модулями. Version-aware rescue adapter має врахувати pending updates та ранні механізми активації; без підтвердженого adapter результат не позначати успішним. Журнал прив'язати до конкретного userdata, framework/version та module ID/version/hash. Файли модулів зберігаються, uninstall/action scripts не запускаються.

Зміна module markers — окрема явно обрана файлова операція до terminal close, а не право image writer записувати userdata. Відобразити ці очікувані зміни в плані; не називати весь сценарій байтово незмінним. Після Android unlock і повторного recovery decrypt відновлювати лише відповідні перевірені модулі окремо або відомими сумісними групами; не вмикати весь старий набір автоматично. Вимкнення модуля не скасовує всі його попередні постійні зміни.

Ця first-boot policy спроєктована, ще не реалізована й не кваліфікована; вона використовує той самий rescue adapter, а не окремий менеджер.

### Послідовність запису образів

1. Перевірити immutable plan та актуальні identities повторно перед записом.
2. Штатно завершити decrypt/mount sessions, які конфліктують з записом системних розділів. Закрити перенесені mounts і services перед зміною їх runtime source.
3. Перевірити rollback coverage і доступний носій; розмір system часто перевищує чинний 64 MiB auto-backup limit.
4. Записувати лише дозволений набір через existing flash journal/readback. Новий raw writer не потрібний.
5. Installer не отримує write-доступ до userdata/metadata/EFS, firmware chain або сторонніх розділів; cache/misc/reboot metadata мають окремий мінімальний відомий контракт.
6. Штатна password authentication може робити нормальні EFS counter writes. Це не installer write, але весь сценарій не слід називати абсолютно read-only.
7. У preserve гілці немає android_data(), reset_android(), mkfs, wipe чи переходу до clean-install після помилки.
8. Зберегти evidence/transaction status, повернутись у fresh recovery і перевірити target profile та доступ до поточних даних до першого Android boot.
9. Після першого завантаження target Android і штатного unlock перевірити apps/files, повернення у recovery та decrypt актуального нового key epoch.

Post-flash/pre-Android decrypt доводить доступ до попереднього key epoch; він не доводить decrypt після законної міграції ключів Android. Вимагати незмінного hash keyblob після upgrade неправильно. Recovery verification сам не повинен ініціювати необґрунтований upgradeKey.

## 6. BOOT, AVB та повернення

BOOT hash не є універсальним критерієм format. Поточний root.py описує історичний mount failure при modified BOOT зі stock vbmeta та одноразовий reset після зміни verification state; він же описує наступні root updates без reset. ui/android_ui.h містить історичний запис Magisk → stock → APatch → stock → Magisk зі збереженням data. Це аргумент проти blanket rule, а не нова кваліфікація поточного data epoch.

Для кожного переходу потрібні фактичні version-binding/AVB умови. Не міняти bootloader lock state або firmware chain заради keep-data режиму.

### До першого target boot

Rollback системних образів значно простіший, якщо збережено весь потрібний попередній набір і не змінено інші стани. Успіх часткового partition writer rollback не означає повного rollback інсталяції.

### Після target boot

Новий Android міг мігрувати databases, upgrade/delete hardware-backed key blobs або змінити secure state. Повернення старого system/boot не гарантує decrypt чи запуск попереднього Android. Raw userdata+metadata backup не є знімком RPMB/TEE.

Не відновлювати старі EFS/counter snapshots як спосіб «повернути пароль» або скидати counters. Копія захищає від окремих видів втрати файлів, але не створює універсальну portability hardware keys.

### Як уникати повного копіювання userdata надалі

Для вже кваліфікованого звичайного upgrade копіювати весь userdata при кожній операції технічно не обов'язково. Можна оновлювати дозволені system images без wipe. При цьому не називати операцію гарантовано зворотною після першого boot.

F2FS checkpoint / Android User Data Checkpoint — перспективний окремий етап для швидкого rollback. Потрібні сумісні Android kernel, init/vold та KeyMint deferred key deletion, а не лише recovery block COW. AOSP описує commit на LOCKED_BOOT_COMPLETE; це може бути раніше за перевірку CE unlock. Потрібен перевірений commit boundary. COW на тому самому origin, який захищає, без правильного persistent layout/first-stage інтеграції не пропонувати як готовий розв'язок.

## 7. Модулі: окрема задача

### P0: менеджер для відновлення запуску

Використати вже перевірений authenticated RO/RW Files lifecycle та PinnedVolume/operation lock. Визначати реальний framework і його версію; сама папка /data/adb/modules не відрізняє Magisk, APatch і KernelSU.

Дії:

- список ID/name/version/framework/status;
- вимкнути модуль або всі підтримувані модулі;
- увімкнути назад;
- позначити видалення на наступний Android boot і скасувати цей стан;
- резервна копія конкретного модуля й попереднього стану через existing archive mechanism;
- зрозумілий діагностичний результат і точна область наступного boot.

Для Magisk/APatch використати документовані disable/remove semantics з перевіркою поточної версії. Не виконувати action.sh/uninstall.sh просто в mainline recovery. Видалення завершує штатний framework у правильному Android середовищі.

Для KernelSU не обмежуватися touch disable: сучасні версії мають metadata/modules.rc та preinit копії, які штатний ksud підтримує узгоджено. Потрібен окремий version-aware adapter і підтримуваний runtime. Невідому версію спочатку показувати read-only. Поточний a22x root installer пропонує Magisk/APatch; KernelSU не є першою ціллю.

### P1: встановлення сумісного Magisk module ZIP

Розширити zip_install.py::describe() та Room для module profile. Перевіряти package ID/format, framework/version, ABI/API, available space, вимоги customize.sh та recovery compatibility. Для підтримуваного recovery installation використовувати офіційний module_installer та функції встановленого Magisk, коректні ownership/mode/SELinux labels і мінімальну потрібну область /data/adb.

Відокремити module write capabilities від ROM/kernel updater capabilities. Наявність chroot/pivot_root не гарантує сумісності Android services. Не підміняти BOOTMODE=true для Android-only модулів і не повідомляти success після простого unzip.

Встановлення нового/оновленого модуля має залишити журнал, можливість повернути попередню версію та чистий результат після помилки; перевірити стійкість через нормальний unmount/remount.

### APatch і KernelSU

Офіційні guides не підтримують установку їх модулів у custom recovery. Не плутати це з установкою самого root. Якщо пакет потребує Android, показувати цей статус. Передача до existing Android companion/manager після запуску — можливий майбутній supported path, але це не «модуль встановлено в recovery» і не заміна прямій установці там, де вона можлива.

## 8. Що не переносити заради паритету з OrangeFox

ZIP engine, sideload, flash/backup, terminal, MTP/ADB, файловий менеджер/архіви, root install, recovery self-update і теми вже мають аналоги.

MIUI/Flyme OTA survival не є generic механізмом для Samsung; офіційний старий guide позначено obsolete. DFE/disable encryption не відповідає цілі збереження існуючого encryption. Дубль AromaFM, init.d addon або App Manager заради назви не є пріоритетом.

Backup UI варто уточнити: raw encrypted userdata, розшифровані app data, shared media та вибірковий перенос — різні результати. Не дублювати існуючий повний raw backup, якщо потрібна саме зворотна копія тієї самої системи.

Окремі користувачі/робочі профілі Android потребуватимуть per-user credential і qualification. Це релевантна майбутня функція OrangeFox, але вона не входить у нинішній user0 PASS і не потрібна для першого preserve transition.

## 9. Порядок реалізації та критерії приймання

| Етап | Результат | Критерій |
| --- | --- | --- |
| 0 | Завершений UI audit Terra | Скріншоти/маршрути, конкретні виправлення, перевірені змінені екрани; format тільки auth+cancel |
| 1 | Android preflight/analyzer без запису | На поточному й target image детермінований manifest; unknown не перетворюється на supported; жодного flash/reset |
| 2 | Module rescue manager | На визначеному framework disable/enable/revoke/marker persistence без root/OS перевстановлення |
| 3 | Native keep-compatible install policy | У всіх entry points план і executor узгоджені; protected userdata/metadata; жодного format fallback |
| 4 | Перша фізична source→target кваліфікація | Повний rollback coverage до boot, decrypt до/після target boot, Android unlock/apps/files, return recovery |
| 5 | Magisk module installation | Один відомий recovery-compatible модуль, update/failure recovery, unmount/remount, Android activation |
| 6 | Вибіркова app migration / checkpoints | Окремі supported schemas/commit boundaries; жодної обіцянки універсального all-data rollback |

Meaningful offline tests: package/path/extent tampering; зміна source після preview; відсутній target profile; несумісний VINTF/fstab; downgrade policy; відсутня велика rollback copy; unexpected target; partial writer failure/recovery. Для preserve-тестів recording writer має довести нуль userdata/metadata/mkfs/reset calls. Тести UI мають перевіряти відображений реальний plan, не лише наявність кнопки.

Фізичні тести не повторювати для лічильника: після достатнього позитивного evidence перевіряти тільки конкретні нові ризики. Неправильні паролі, зміна credential або форматування не потрібні для UI-аудиту.

## 10. Первинні джерела

Переглянуто 17.11.2026. Посилання пояснюють архітектуру; вони не є доказом працездатності конкретного target ROM на a22x.

- [AOSP: File-based encryption](https://source.android.com/docs/security/features/encryption/file-based)
- [AOSP: Metadata encryption](https://source.android.com/docs/security/features/encryption/metadata)
- [AOSP: KeyMint version binding](https://source.android.com/docs/security/features/keystore/version-binding)
- [AOSP: VINTF match rules](https://source.android.com/docs/core/architecture/vintf/match-rules)
- [AOSP: User Data Checkpoint](https://source.android.com/docs/core/ota/user-data-checkpoint)
- [AOSP: Dynamic System Updates](https://source.android.com/docs/core/ota/dynamic-system-updates)
- [Android Developers: App updates](https://developer.android.com/google/play/app-updates)
- [Magisk: Module developer guide](https://topjohnwu.github.io/Magisk/guides.html)
- [KernelSU: Module guide](https://kernelsu.org/guide/module.html)
- [KernelSU: Rescue from bootloop](https://kernelsu.org/guide/rescue-from-bootloop.html)
- [APatch: APM guide](https://apatch.dev/apm-guide.html)
- [OrangeFox: Encryption](https://wiki.orangefox.tech/guides/encryption)
- [OrangeFox: obsolete MIUI/Flyme OTA](https://wiki.orangefox.tech/guides/ota)
- [TWRP: Backup exclusions](https://twrp.me/faq/backupexclusions.html)
