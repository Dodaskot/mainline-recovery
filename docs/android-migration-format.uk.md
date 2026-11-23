# A22x Android Migration

Ідентифікатор формату — `a22x.android-migration.v1`. Один файл `.tar.gz.enc` містить вибрані дані застосунків Android та, за запитом, спільні файли. Формат адресує застосунки за назвою пакета та поточними сертифікатами підпису. UID джерела записується для діагностики. Android на іншому пристрої може призначити власний UID.

## Що копіюється

- Приватні файли вибраних застосунків основного користувача 0. `apps/<package>/ce/` містить дані, доступні після автентифікації, а `apps/<package>/de/` — приватні дані Direct Boot. Копіюються звичайні файли та каталоги, включно з наявними файлами SQLite WAL.
- `shared/` за запитом містить спільні файли з `/data/media/0`, включно з `Android/media`. `Android/data`, `Android/obb` і відомі каталоги копій recovery виключаються.
- Каталоги застосунків `cache`, `code_cache` і `lib`, симлінки та спеціальні файли пропускаються. Переносна копія має окремі розділи для налаштувань, особистих даних та APK. Дані застосунків, які потребують ключа Android Keystore з попереднього пристрою, можуть потребувати повторного входу або експорту самим застосунком. [Android Keystore](https://developer.android.com/privacy-and-security/keystore)

Поточний запис із Recovery підтримує пакети з внутрішнього `/data/app` із власним app UID. Ідентичність береться з `/data/system/packages.xml` у форматі XML або ABX. Для CE основного користувача використовується реальний `/data/data`, якщо цей каталог є, інакше `/data/user/0`. [AOSP Settings](https://android.googlesource.com/platform/frameworks/base/+/master/services/core/java/com/android/server/pm/Settings.java), [AOSP installd](https://android.googlesource.com/platform/frameworks/native/+/b68dc25365978e09554dc5828f0dea8fb35faf3a/cmds/installd/utils.cpp)

## Контейнер

Внутрішній потік — POSIX PAX tar у gzip. Tar містить унікальні відносні шляхи UTF‑8, каталоги перед нащадками, тільки звичайні файли та каталоги, UID/GID 0 і біти режиму доступу в межах `0777`. Останній запис — `manifest.json` з унікальними ключами JSON.

| Поле | Значення |
| --- | --- |
| `schema`, `android_user` | `a22x.android-migration.v1`, ціле число `0` |
| `source` | `sdk` і `fingerprint` джерела |
| `items[]` | Для `app-data` — `package`, `uid`, `version_code`, відсортовані `signers_sha256`, присутні `scopes` і `keystore_exported: false`. Для `shared-files` — `skipped`. |
| `files` | Індекс усіх членів tar, крім маніфесту. Для кожного шляху записано `type`, `size`, `mode`, `mtime` в секундах від Unix epoch і `sha256`. Для каталогу розмір дорівнює `0`, SHA-256 дорівнює `null`. |

Записані для scope або `skipped` лічильники мають поля `cache`, `links_or_special` та `excluded_paths`. SHA-256 файлів і сертифікатів подано 64 малими шістнадцятковими символами. Сертифікат хешується в байтовому представленні, яке зберіг PackageManager. Перевірник зіставляє фактичні дані й метадані tar з повним індексом.

Зовнішня оболонка використовує наявний формат `a22xenc1`. Розташування байтів таке.

```text
ASCII "Salted__" | salt[8] | AES-256-CTR ciphertext[N] |
HMAC-SHA256[32] | password_check[8] | N (uint64 LE) | ASCII "a22xenc1"
```

PBKDF2-HMAC-SHA256 обчислює 48 байтів за 600 000 ітерацій із фрази UTF‑8 і цієї випадкової солі. Перші 32 байти — ключ AES, решта 16 — початковий лічильник CTR у big-endian. Ключ HMAC — `HMAC-SHA256(aes_key, b"a22x archive mac")`. HMAC покриває заголовок, сіль та весь ciphertext. `password_check` — перші 8 байтів `HMAC-SHA256(mac_key, b"a22x password check")`. Перевірник перевіряє розмір, HMAC і повний маніфест. Відкритий gzip під час створення передається через канал у пам’яті. На диск записується тільки зашифрований архів, який публікується після перевірки.

## Команди

Для копії на SD або USB розблокуйте Data в Recovery. Достатньо змонтувати Data для читання та зовнішній носій для запису. Для збереження копії на самому Data цей том має бути доступним для запису. Свіжі `volume_token` та ідентифікатор SD або USB повертає `python3 /opt/a22x-recovery/filesystem.py --device inventory`. Файл із фразою для копії на Recovery має лежати в приватному каталозі в RAM. Фраза копії окрема від PIN Android.

У Recovery відкрийте «Резервні копії → Android → Перенести на інший Android → Дані застосунків». Виберіть окремі пакети або натисніть «Вибрати всі», якщо список уміщається в одну копію. Після збереження вибору утримуйте кнопку створення копії й введіть пароль архіву. В одну копію можна додати до 256 пакетів. Номер версії, підпис і власника файлів Recovery перевіряє за реєстром установлених застосунків.

Параметр «Додавати APK» додає `base.apk` і split APK вибраних пакетів із внутрішнього `/data/app`. Копія тоді використовує `a22x.android-migration.v4`. Маніфест зберігає точний список APK і SHA-256 кожного файла під `apps/<package>/apk/`. Приватні дані залишаються під `ce/` і `de/`. Перед встановленням утиліта на ПК перевіряє назву пакета, версію, підпис та унікальність split через Android SDK Build Tools. З `--apply` вона передає весь комплект штатному Package Manager розблокованого Android. Після цього приватні дані можна відновити в Recovery.

```sh
python3 /opt/a22x-recovery/android_migration.py --device --password-file "$passfile" create \
  --expected-volume-token "$data_token" --destination-volume "$sd_volume" \
  --expected-destination-token "$sd_token" --package org.example.notes --include-apks --include-shared --confirm

python3 tools/android_restore_apks.py --build-tools "$build_tools" --password-file "$passfile" \
  --expected-sha256 "$archive_sha256" --serial "$adb_serial" --user 0 --package org.example.notes \
  --apply "$archive"
```

На Linux можна перевірити копію через `--offline`, передати відомий SHA-256 через `--expected-sha256` і за потреби створити новий **незашифрований** tar.gz з правами `0600`. Опція `--manifest` повертає весь індекс у JSON.

```sh
python3 android_migration.py --offline --password-file "$passfile" verify \
  --path "$archive" --export-tar "$new_tar"
```

### Відновлення контактів

`android_restore_contacts.py` перевіряє архів і показує кількість контактів. З `--apply` утиліта додає імена, телефони й адреси електронної пошти до локальної адресної книги розблокованого користувача Android. Якщо в одному наявному записі вже є ім’я й усі ці номери та адреси, утиліта зараховує його як відновлений. Запис і перевірка локального акаунта виконуються в одній транзакції Contacts Provider. [Android Contacts Provider](https://developer.android.com/identity/providers/contacts-provider)

```sh
python3 tools/android_restore_contacts.py --password-file "$passfile" \
  --expected-sha256 "$archive_sha256" "$archive"

python3 tools/android_restore_contacts.py --password-file "$passfile" \
  --expected-sha256 "$archive_sha256" --serial "$adb_serial" --user 0 \
  --build-tools "$build_tools" --android-jar "$android_jar" --apply "$archive"
```

Для запису потрібні Android 11 або новіший, ADB, JDK і Android SDK Build Tools. Утиліта збирає й встановлює тимчасовий підписаний помічник, передає йому дані через приватний каталог і видаляє помічник після операції.

### Відновлення даних застосунків

У Recovery `verify --volume "$archive_volume" --expected-volume-token "$archive_token" --path "$archive_path" --review-for-data-token "$data_token"` читає реєстр розблокованого цільового Android. `identity_matches` означає збіг імені, набору поточних підписів і версії застосунку за умови, що на цілі такий самий або новіший Android SDK.

У «Файлах» відкрийте дії архіву `.tar.gz.enc` і виберіть «Дані застосунків». Введіть пароль копії, виберіть встановлений застосунок, для якого підтверджено збіг пакета, й утримуйте «Відновити». Для запису потрібно змонтувати розблокований Data в режимі запису перед відкриттям архіву.

`restore-app` відновлює приватні файли одного встановленого застосунку користувача 0. На цільовому Android застосунок має бути встановлений із підготованими каталогами для CE та DE. У recovery відкрийте Data для запису. Після перевірки SHA‑256, пароля архіву та ідентичності пакета команда відновить файли з UID/GID, міткою SELinux і політикою шифрування цільового застосунку.

```sh
python3 /opt/a22x-recovery/android_migration.py --device --password-file "$passfile" restore-app \
  --volume "$archive_volume" --expected-volume-token "$archive_token" --path "$archive_path" \
  --expected-sha256 "$archive_sha256" --expected-target-token "$data_token" \
  --package org.example.notes --confirm
```

Конфлікт із наявними файлами повертає `APP_RESTORE_CONFLICT` до зміни цілі. Повтор команди перевіряє вже відновлені дерева файлів і доповнює відсутні. Каталоги, створені Android для застосунку, зберігають свої inode.

Команда `restore-shared` у recovery відновлює спільні файли в новий каталог `/data/media/0/Restored-Migration-<24 символи SHA-256>`. Для запуску потрібні SHA-256 перевіреної копії, її пароль, змонтований носій та доступ до цільового Data для запису. Перед публікацією каталогу recovery перевіряє вміст файлів. Повторна спроба створити той самий каталог повертає `DESTINATION_EXISTS`. Приватні дані застосунків доступні для експорту на Linux.

```sh
python3 /opt/a22x-recovery/android_migration.py --device --password-file "$passfile" restore-shared \
  --volume "$archive_volume" --expected-volume-token "$archive_token" --path "$archive_path" \
  --expected-sha256 "$archive_sha256" --expected-target-token "$data_token" --confirm
```

## Усі дані для цієї моделі

У recovery відкрийте **Резервні копії → Android → Усі дані для цієї моделі**. Виберіть Data, SD або USB, утримайте кнопку створення й задайте пароль щонайменше з восьми символів. Копії на SD та USB доступні після форматування внутрішнього сховища.

Профіль `same-model` зберігає дерево розшифрованого розділу userdata для пристрою з одним користувачем Android. Разом з особистими файлами до нього входять дані системних застосунків, налаштування Android, файли конфігурації Wi‑Fi, бази локальних контактів, домашнього екрана, встановлені у Data APK і супутні файли баз даних. Сканування охоплює всі доступні шляхи незалежно від назви пакета лаунчера або постачальника контактів. Операційна система в розділах boot, system, vendor та інших розділах до копії не входить. Вміст хмарних сервісів доступний у межах локальних файлів телефона.

Новий контейнер `a22x.android-model-data.v1` має розширення `.tar.zst.enc`. Всередині — zstd/PAX із шляхами під `payload/`, правами, власниками, часовими мітками, розширеними атрибутами і маніфестом. Маніфест фіксує модель із завантажувача, кодову назву з дерева пристроїв, Android SDK та відбиток збірки з PackageManager. Архів захищений паролем і повністю перевіряється перед публікацією. Відомі каталоги копій, сокети й вузли пристроїв пропускаються, їхні кількості записуються в результат. За виявлення додаткового користувача, недоступного файла або зміни дерева під час копіювання операція завершується помилкою.

```sh
python3 /opt/a22x-recovery/android_migration.py --device --password-file "$passfile" create \
  --profile same-model --expected-volume-token "$data_token" --destination-volume "$archive_volume" \
  --expected-destination-token "$archive_token" --confirm
```

Команда `verify` автоматично розпізнає цей формат. На Linux параметр `--export-tar /шлях/копія.tar.zst` створює новий розшифрований архів із правами `0600`. На розблокованому телефоні `--review-for-data-token` окремо показує збіг моделі й збірки Android. Ці перевірки описують сумісність джерела. Для запису системних баз у діючу систему потрібне відновлення з урахуванням цільової прошивки. Апаратні ключі та облікові дані, прив’язані до пристрою, потребують окремого опрацювання навіть для іншого SM-A226B.

### Контакти для іншого Android

На Linux утиліта `tools/android_contacts_vcard.py` бере зашифрований архів профілю `same-model`, перевіряє його та створює файл vCard 3.0 для імпорту на інший телефон. Вона читає локальні контакти стандартного постачальника Android, враховує журнал SQLite WAL, об’єднує записи за ідентифікатором контакту та експортує імена, телефони й електронні адреси. Фото, групи й додаткові поля залишаються в оригінальній базі всередині копії. Тимчасова база розміщується у приватній папці біля нового VCF на час перетворення. Новий VCF містить відкриті контактні дані й має права `0600`. [Імпорт VCF на Android](https://support.google.com/contacts/answer/15147365?co=GENIE.Platform%3DAndroid&hl=en)

```sh
python3 tools/android_contacts_vcard.py --password-file "$passfile" --expected-sha256 "$archive_sha256" \
  "$archive" /шлях/контакти.vcf
```

### Початкова розкладка Launcher3 на іншому Android

На Linux `tools/android_workspace.py` читає розкладку із зашифрованої повної копії разом із журналом SQLite. Для основного користувача переносяться значки встановлених застосунків, сторінки й клітинки, позиції нижньої панелі, назви папок і порядок їхнього вмісту. Для віджетів XML містить компонент і розмір. Їхню конфігурацію надає віджет на цільовому телефоні. Інструмент повідомляє кількість пропущених записів, зокрема ярликів зі спеціальними діями й записів іншого профілю.

```sh
python3 tools/android_workspace.py --password-file "$passfile" --expected-sha256 "$archive_sha256" \
  "$archive" workspace.xml
python3 tools/launcher-layout-provider/build.py --build-tools "$android_build_tools" \
  --android-jar "$android_jar" workspace.xml workspace-layout.apk
```

Стандартне джерело — `com.android.launcher3/databases/launcher.db`. Параметри `--package` та `--database` дозволяють вказати інший лаунчер з відповідною схемою таблиці `favorites`. Експорт із One UI Home потребує окремої перевірки на реальній базі Samsung.

Друга команда використовує Android SDK Build Tools і JDK та виводить `authority` створеного APK. APK містить приватну розкладку й підписується одноразовим локальним ключем. Для встановлення у **новий профіль**, поки Launcher3 ще не створив свою базу, використовуйте його ідентифікатор і серійний номер цільового пристрою.

```sh
adb -s "$serial" install --user "$user_id" workspace-layout.apk
adb -s "$serial" shell settings --user "$user_id" put secure launcher3.layout.provider "$authority"
```

Під час першої ініціалізації Launcher3 запитує XML у постачальника та створює власні записи ідентифікаторів. Програми, значки яких переносяться, мають бути встановлені у профілі призначення. Для збереження координат потрібна сітка з достатньою кількістю клітинок і позицій нижньої панелі. Метод перевірено в новому профілі AOSP Launcher3 на Android 14. Поточна розкладка вже ініціалізованого профілю та механізм імпорту Samsung One UI Home потребують окремої підтримки. [Завантаження початкової розкладки в AOSP](https://android.googlesource.com/platform/packages/apps/Launcher3/+/6df1743d23595bc9b800c9e81fcaae085ad47951/src/com/android/launcher3/model/ModelDbController.java)

### Перенесення мережі Wi-Fi через QR-код

На Linux перша команда виводить назви мереж, індекси та доступність перенесення. Друга створює приватний PNG для вибраної мережі за допомогою `qrencode`. Відскануйте його у налаштуваннях Wi-Fi іншого телефона та підтвердьте підключення. PNG містить облікові дані мережі у формі, яку може прочитати кожен, хто бачить зображення.

```sh
python3 tools/android_wifi_qr.py --password-file "$passfile" --expected-sha256 "$archive_sha256" "$archive"
python3 tools/android_wifi_qr.py --password-file "$passfile" --expected-sha256 "$archive_sha256" \
  --network 1 --output мережа.png "$archive"
```

Утиліта читає файли WifiConfigStore.xml AOSP для власника пристрою та спільні мережі. Вона переносить назву, тип захисту, доступний пароль і ознаку прихованої мережі. Підтримуються відкриті мережі, WPA/WPA2 Personal і WPA3 Personal із сумісним сканером. Для окремо зашифрованого ключа список показує `encrypted_key`. Корпоративні мережі з сертифікатами, IP-параметри та проксі потребують налаштування на цільовому телефоні. [Формат конфігурації AOSP](https://android.googlesource.com/platform/packages/modules/Wifi/+/c6e2a6083b342a9196091f17ab5276cac8f4d2b3/service/java/com/android/server/wifi/util/XmlUtil.java) · [Формат QR у налаштуваннях Android](https://android.googlesource.com/platform/packages/apps/Settings/+/master/src/com/android/settings/wifi/dpp/WifiNetworkConfig.java)

### Спільні файли та системні налаштування для іншого телефона

У recovery виберіть **Резервні копії → Android → Перенести на інший Android**, виберіть носій і задайте пароль. Цей профіль записує фото, документи та інші спільні файли користувача 0 і підтримувані параметри Android в один зашифрований архів. Для командного рядка додайте до `create` параметри `--include-shared --include-settings`. Можна також вибрати лише параметри або додати дані окремих застосунків через `--package`.

Версія `a22x.android-migration.v2` зберігає параметри у полі маніфесту `preferences` за просторами `system` і `secure`. Методи читання підтримують текстовий XML та Android Binary XML. Вибір охоплює розмір шрифту, тайм-аут екрана, формат часу, автоматичний поворот, налаштування вібрації, звуку, субтитрів та доступності. Кожне значення перевіряється за іменем, типом і допустимим діапазоном. Облікові записи, ідентифікатори пристрою, дозволи та прив’язки до компонентів програм залишаються на вихідному пристрої. Перелік реалізованих полів міститься у `android_preferences.py`. [Системні параметри для бекапу в AOSP](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android14-release/packages/SettingsProvider/src/android/provider/settings/backup/SystemSettings.java)

У файловому менеджері recovery відкрийте дії архіву `.tar.gz.enc`, виберіть «На Android» та введіть пароль копії. Після перевірки архіву утримуйте кнопку відновлення. Для запису потрібен розблокований том Data у режимі читання й запису. Спільні файли з’являться в окремій папці `Restored-Migration-…` у внутрішньому сховищі. З командного рядка використайте `restore-shared`. Для налаштувань завантажте Android на цільовому телефоні, розблокуйте потрібного користувача й підключіть його через авторизований ADB. Команда на Linux спочатку покаже, які значення зміняться. Додайте `--apply` до тієї самої команди, щоб застосувати їх і перечитати з SettingsProvider. Повторний запуск пропускає вже збережені значення. Видимий ефект налаштування залежить від можливостей цільового Android. Інструмент також читає повний архів `same-model`.

```sh
python3 tools/android_restore_preferences.py --serial "$serial" --user 0 \
  --password-file "$passfile" --expected-sha256 "$archive_sha256" "$archive"
```

Перед записом `--apply` зберігає попередні значення в приватному журналі на ПК. Якщо запис відхилено, утиліта повертає вже змінені параметри до попереднього стану й перечитує їх. Після розриву ADB або перерваного процесу відкат можна продовжити через будь-яке ADB підключення до того самого пристрою та користувача. Якщо параметр окремо змінився на третє значення, утиліта зберігає це значення і повідомляє назву параметра.

```sh
python3 tools/android_restore_preferences.py --serial "$serial" --user 0 --rollback
```

Для перегляду й застосування потрібен перевірений архів. Відкат читає журнал із `$XDG_STATE_HOME/a22x-recovery/settings` або `~/.local/state/a22x-recovery/settings`. Якщо використовували `--state-dir`, укажіть ту саму папку.

### Контакти, Wi-Fi та розкладка в переносимому профілі

Пункт **Перенести на інший Android** зберігає підтримувані дані власника в зашифрованому архіві `a22x.android-migration.v3`. Для цього у командному рядку є параметр `--include-personal`. Разом із `--include-shared --include-settings` він відповідає вибору в recovery. Інвентар архіву вказує, чи знайдено базу контактів, які пакети домашнього екрана мають розкладку й скільки файлів конфігурації Wi-Fi збережено.

Утиліти `android_contacts_vcard.py`, `android_wifi_qr.py` та `android_workspace.py` читають цей архів за тими самими командами, що й повну копію моделі. Для Launcher3 з окремою базою сітки вкажіть її назву, наприклад `--database launcher_4_by_4.db`. У копію входять база та наявний WAL або журнал транзакцій. Зміна вихідних файлів під час читання скасовує створення копії. Для Wi-Fi й One UI Home діють описані вище обмеження конкретного формату. Попередні архіви v1 і v2 відкриваються своїми наявними операціями.
