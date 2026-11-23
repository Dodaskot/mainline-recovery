# Android compatibility analyzer P0

Дата: 17 листопада 2026 року. База: 068e070.
Статус: реалізований аналізатор і офлайн перевірки; жодна пара збірок
не кваліфікована на телефоні, дозвіл preserve-запису не видається.

## Реалізовано

- Підключення до наявного Files/volume-token контракту без створення mount,
  decrypt-сесій, автентифікації чи запуску TEE.
- Декларативні ZIP із .img, окремі raw/sparse/gzip/xz образи.
  Використано наявні bounded decoders із flash.py / install.py.
  update-binary і будь-які скрипти пакета не виконуються.
- SHA-256 усього пакета та повністю декодованих байтів кожного образу,
  реальний image_bytes, формат, ознака filesystem/boot/vbmeta/dtbo.
  Штучний нульовий хвіст до розміру розділу не входить у hash образу.
- Явний write_set/protected_set. Заборонений або невідомий target не
  відкидається непомітно: він робить report incompatible.
  Явні назви розділів, зокрема system_ext/system_dlkm, зберігаються і в ZIP
  з одним образом. Імена заборонених/невідомих розділів не підміняються system;
  відомі назви GSI є лише підказкою target, а не кваліфікацією сумісності.
- Читання перевірених GPT/LP identities, розмірів, logical extents і metadata;
  повторне читання geometry та source-volume identity наприкінці аналізу.
  У P0 збільшення logical partition не допускається preserve-політикою.
- Необов'язкові вже витягнуті public snapshots: build.prop, визначені fstab,
  VINTF XML, framework JARs та копії images. Без locksettings, spblob,
  app databases, NV і hardware key матеріалу.
- Відомі JAR pairs звіряються з чинним android_profiles.FRAMEWORK_PINS.
  Detached snapshot або файли поруч із system.img не доводять, що саме
  образ або поточний userdata epoch відповідає цим файлам.
- Перевірка заявленого SDK/patch downgrade, явних змін on-disk fstab,
  типів образів, геометрії й rollback gap. Відсутні effective defaults,
  credential/TEE/AVB state, VINTF/kernel результат, app migration та
  module compatibility позначаються unknown.
- Повний manifest_sha256 та revalidate(): підміна пакета, зміна geometry
  або public snapshot після preview відхиляється.
- android_transitions.py містить порожній source-controlled каталог.
  Дані пакета й CLI не можуть додати до нього кваліфіковану пару.

## API та CLI

Python:

    inspect(context, volume, token, path, *, current=None, rollback=None)
    revalidate(context, volume, token, path, expected_manifest_sha256,
               *, current=None, rollback=None)
    collect_current(extracted_public_root)
    analyze_file(target_path, *, current_root=None, target_root=None,
                 rollback_root=None)

current отримують через collect_current(); перед використанням snapshot
повторно читається й хешується. Це перевіряє незмінність snapshot, а не
його відповідність живому телефону.

CLI:

    python3 android_compat.py --device inspect \
        --volume sdcard --volume-token TOKEN --path /target.zip
    python3 android_compat.py --fixture FIXTURE inspect \
        --volume userdata --volume-token TOKEN --path /target.zip
    python3 android_compat.py analyze-files --target /path/system.img.xz \
        --current-root /path/current-public --target-root /path/target-public \
        --rollback-root /path/rollback

Пристроєвий source volume має вже бути змонтований через Files.
Analyzer не монтує його автоматично. Приклад офлайн snapshot:

    current-public/build.prop
    current-public/system/framework/services.jar
    current-public/system/framework/framework.jar
    current-public/vendor/etc/fstab.mt6833
    current-public/images/boot.img
    current-public/images/system.img
    rollback/system.img

Вихідний JSON має ok, schema, status, preserve_allowed, source, target,
write_set, protected_set, geometry, rollback, checks і manifest_sha256.
Статуси окремих checks: supported / incompatible / unknown.
У P0 загальний статус тільки unknown або incompatible і
preserve_allowed завжди false. Supported у рядку означає лише результат
конкретної статичної перевірки, не можливість установки.

Помилки входу повертаються як ok:false,error:{code,message,details}
(exit 2 для policy/identity rejection, exit 3 для unreadable input).

## Межі

P0 не читає build.prop/JAR/fstab зсередини filesystem image. Для такого
читання наступний етап потребує окремого bounded image reader або
перевіреного extraction receipt, прив'язаного до exact image hash.
Наявні sidecar facts не перетворюються на trusted source чи target.

Payload/block OTA, Samsung tar та інші compressed formats не отримують
preserve-дозволу. Їх підтримка в загальному installer не означає, що
preserve-контракт для них уже реалізований.

Порівняння окремих fstab рядків не розв'язує залежність defaults від
first API/vendor. inlinecrypt як mount option саме по собі не є доказом
зміни on-disk формату. Невідомі defaults залишаються unknown.

Rollback report показує automatic limit 64 MiB і фактичні відсутні/неправильні
копії. Навіть копія, яка збігається з detached source snapshot, не отримує
статус повного rollback живого пристрою. Після першого target boot не
обіцяється повернення app schemas або secure state старими образами.

Окремий preserve executor мусить заново перевірити незмінний plan,
власність operation lock, live source/key epoch, правильний transition
record, повну rollback coverage і завершення конфліктних runtime sessions.
P0 не є таким executor.

## Перевірки

30 змістовних fixture tests у tests/test_android_compat.py:
детермінованість і decoded hashes; відсутність mount/unmount/flash/reset;
невідомий/відомий detached profile; stale current snapshot; target tamper
зі збереженим розміром/mtime; зміна geometry identity; downgrade;
fstab disk-format vs mount-only flag; protected target; ZIP traversal,
symlink, duplicate member/partition; single-image partition mapping, заборонені/невідомі та slot-suffixed targets,
GSI aliases; malformed sparse extents; raw/xz/sparse;
завеликий image; відсутній rollback для великого розділу; невірна копія;
symlink/hardlink snapshot; OTA wipe/downgrade metadata та incremental source mismatch; CLI JSON.

Команда:

    python3 -m unittest discover -s tests -p test_android_compat.py -v

Hardware commands/flash/auth під час цієї реалізації не виконувались.
Фактичний телефон і встановлений recovery не змінювалися цим агентом.

## Первинні джерела

Перевірено 17.11.2026:

- [AOSP FBE](https://source.android.com/docs/security/features/encryption/file-based):
  формат шифрування, залежності KeyMint/Gatekeeper/TEE і окремі CE/DE умови.
- [AOSP KeyMint version binding](https://source.android.com/docs/security/features/keystore/version-binding):
  окремі OS/system/vendor/boot bindings; upgradeKey та видалення попереднього
  keyblob не відновлюються просто поверненням попереднього system.img.
- Вихідний узгоджений план:
  [android-preserve-data-and-modules-20261117.uk.md](android-preserve-data-and-modules-20261117.uk.md).
