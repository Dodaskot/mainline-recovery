# Апаратна перевірка reusable CE sessions — 17 листопада 2026 року

## Результат і точний образ

**PASS для наведеної матриці на встановленому image05.** Підтверджено
повторні RO/RW монтування без reboot між ними, політики `each_mount`,
`first_access` і `startup` та свіжу парольну авторизацію перед форматуванням.

Обсяг: лише `evolutionx-a226b-a16`, Evolution 16, credential type `password`,
Android user `0` на цьому A22x. Фізичне форматування/reset/стирання, неправильний
пароль на hardware, touch/keyboard submit або cancel у UI та UI auto-unmount
не перевірялися. Інші профілі й образи цим результатом не кваліфікуються.

| Поле | Значення |
| --- | --- |
| Версія / образ | `1.1.0-dev-evox-session4` / `image05/recovery.img` |
| Розмір | `41943040` bytes |
| SHA-256 образу | `0211b85a6250a712b85037989d23e47b1cc4d27392ed4eb5032f9b686d34e03a` |
| Source commit образу | `a6c3dcc5873413908e28d06fdef53ad05ce41e3b` |
| SHA-256 UI binary | `59834c5fb008a906af99096ef0e6d8752ffd049fc069848f5d8c7abfad89517d` |
| SHA-256 hardware source pins | `0efc3c8438fdff2e8bce0e738a8f9c4692e9dbbbcc69ff53c9af40dc28aaba9a` |

Аудит `image-audit04` підтвердив source/UI identity, повний Python manifest,
дозволені cpio changes, boot geometry/components, AVB та kernel/module ABI.
Harness03 прив'язаний до фактичних 87 файлів image05, включно з 79 Python
sources. Live receipts мають `runtime_overlay=false` і
`qualification_edited=false`. Наступні documentation-only commits не змінюють
source commit уже зібраного образу.

## Де зберігаються докази

```text
B=$HOME/a22x-work/artifacts/lk-recovery-bridge-20261114/stage-c/password-sp/permanent-rw-backup-20261116
A=B/reusable-session-20261117
```

У наведених нижче шляхах `A` і `B` означають ці каталоги host.

| Завантаження | Boot UUID | Run |
| --- | --- | --- |
| Each mount, first access, marker, format authorization | `c5d11731-c7e3-4b2c-ab40-b479e208dbdf` | `gui05a699b814c929` |
| Startup | `eddc6d00-55b7-4c5e-9057-916b1d05e750` | `gui31c12b99e0726f` |
| Фінальний idle | `460942c9-338d-474e-b352-14a957e28bab` | Нової credential операції немає |

Reboot був явною межею між цими завантаженнями. Усередині cached RO/RW
циклів reboot не було; обидві credential-сесії завершені terminal close.

## Each mount і first access

Основна сесія зберігала native owner `PID=509, starttime=6994` до terminal
close. Fresh authentication змінює auth ID/generation; suspend/remount
змінюють mount/native epochs.

| Completed receipt / крок | Фактичний результат | Auth generation | Mount generation |
| --- | --- | --- | --- |
| `session-live03/AUTH.stdout` | Fresh password, RW, `each_mount` | `0 → 1` | `0 → 1` |
| `CYCLE-s4-01-suspend-each` | Реальний suspend | `1` | `1 → 2` |
| `CYCLE-s4-02-each-reject` | Без credential: `CREDENTIAL_REQUIRED`, стан і epochs незмінні | `1` | `2` |
| `session-first-access02/AUTH.stdout` | Fresh password після зміни policy, RW, новий auth ID | `1 → 2` | `2 → 3` |
| `s4-06-suspend-a` → `s4-07-cached-ro-a` | Suspend → cached RO | `2` | `3 → 4 → 5` |
| `s4-09-suspend-b` → `s4-10-cached-rw-b` | Suspend → cached RW | `2` | `5 → 6 → 7` |
| `s4-12-suspend-c` → `s4-13-cached-ro-c` | Suspend → cached RO | `2` | `7 → 8 → 9` |
| `CYCLE-s4-15-suspend-for-format` | Suspend перед format authorization | `2` | `9 → 10` |

Усі cycle receipts цієї таблиці містяться в `B/session-live03` як
`CYCLE-<step>.outcome.json` та `CYCLE-<step>-RESULT.json`.
Три cached mounts зберегли auth ID `602541f0a981aabe3ac7455d8155ac8c`,
`auth_generation=2` і owner; кожен має `authentication_performed=false`
та `credential_submissions=0`. Kernel proofs підтвердили actual RO/RW
і повний detach. Повторний числовий `mount_id` не трактувався як безперервний
mount: перевірялися detach proofs і монотонні epochs.

## 64 KiB: запис, RO readback, rename/delete, відсутність

Один окремий контрольний файл мав розмір `65536` bytes і SHA-256:

```text
f9d134e6fec4cb7dfd8090ad37d55dec3a381587b4fb71bd35787481ca85ca2e
```

| Marker receipt у `B/session-live03` | Доказ |
| --- | --- |
| `MARKER-s4-05-marker-create.outcome.json` | Власний inode; `fsync` файлу та каталогу |
| `MARKER-s4-08-marker-read.outcome.json` | Після повного unmount та RO mount прочитано всі bytes з тим самим SHA-256 |
| `MARKER-s4-11-marker-delete.outcome.json` | Після RW mount перевірено inode, виконано rename/delete та `fsync` каталогу |
| `MARKER-s4-14-marker-absent.outcome.json` | Після наступного unmount/RO mount відсутні початковий і перейменований шляхи |

Marker operations самі не викликали auth, mount, unmount або format: це
окремі кроки матриці. Підтверджено збереження запису й видалення через
unmount/remount; тест втрати живлення не проводився.

## Свіжа Format Data authorization без форматування

`B/session-format02-final/AUTH-RESULT.json`:
`REUSABLE_FRESH_FORMAT_AUTH_CANCEL_PASS`. З початкового
`session_unmounted`, auth `2` / mount `10`, normal Files API виконав
fresh native password verification через FD з тим самим owner:

- auth `2 → 3`, новий auth ID; mount `10 → 11`, перевірений RO mount;
- grant незалежно валідований і явно скасований;
- після cancel validator повернув `FORMAT_AUTH_CONSUMED`,
  `used_reason=cancelled`; RO mount/session не змінилися;
- старий volume token відхилено;
- `format_invocations=0`, `reset_invocations=0`, `data_erased=false`.

Це доказ fresh authentication, binding і revoke/consumed gate. Деструктивний
writer, mkfs та reset не запускалися; цей результат не є physical format test.

## Startup: actual UI preparation, RO auth, cached RW/RO

`B/session-startup01/STARTUP-PREPARED.json` підтверджує реальну UI-created
prepared session: profile/password/user0, усі чотири epochs `0`, null auth
identity і порожній key cache. Host admission мав `prepare_calls=0` та
`credential_deadline_extended=false`; marker і prepared identity не змінювалися.
Root використав уже підготовлену сесію. Сам marker не доводить показ prompt
або автентифікацію.

`AUTH-RESULT.json` має `STARTUP_PREPARED_PASSWORD_RO_PASS`: один normal
Files credential mount, actual RO, auth `1` / mount `1`, native owner
`PID=531, starttime=4369`. Далі:

| Completed cycle у `B/session-startup01` | Результат | Auth / mount generation |
| --- | --- | --- |
| `startup-01-suspend` → `startup-02-cached-rw` | Normal unmount → cached RW | auth `1`; mount `1 → 2 → 3` |
| `startup-03-suspend` → `startup-04-cached-ro` | Normal unmount → cached RO | auth `1`; mount `3 → 4 → 5` |
| `startup-05-terminal-close` | Terminal close з cleanup proof | Окремий terminal receipt |

Auth ID `bac740600081f1f195b635fbaa775176` та owner збереглися; обидва
cached mounts мають `authentication_performed=false` і нуль credential
submissions. Початковий доказ залишається **RO**; RW доведений наступним
`startup-02`. У результаті явно збережені
`physical_ui_submit_tested=false` і `ui_auto_unmount_tested=false`:
credential mount і окремий unmount виконані normal Files API/harness, а не
фізичним UI submit чи UI completion path.

## Native counters і terminal cleanup

Незалежні read-only аудити взяли лічильники з completed native cleanup proofs;
це не підрахунок лише host commands.

| Credential boot | Auth attempts | Auth successes | Gatekeeper calls | Fresh password operations |
| --- | --- | --- | --- | --- |
| Основна матриця `c5d…` | 3 | 3 | 6 | each_mount, first_access, format authorization |
| Startup `eddc…` | 1 | 1 | 2 | startup RO authentication |
| Разом | **4** | **4** | **8** | **4** |

Усього **5 cached mounts**, **0 cached credential submissions**.
Лічильники не показують додаткової native authentication під час cached
mounts, suspend, marker operations або close.

Обидва close підтвердили `session_closed=true`, `session_retained=false`,
`cleanup_verified=true`, порожній key cache, reaped native owner/runtime,
відсутність owned crypto DM, `retained_physical_holders=0` та
`block_mount_devices=0` у перевірених mount namespaces. Watchdog observation
після cleanup залишався на тому самому boot протягом `17.117` s та `17.122` s
відповідно для основної та startup-сесії.

## Фінальний idle і UART

Після startup close нормальний settings setter повернув `each_mount`,
підтвердив persistence і збереження інших settings. Root явно перезавантажив
recovery без нової авторизації. `B/session-final-idle03/FRESH-IDLE.json`:
`FRESH_RECOVERY_IDLE_PASS` на фінальному boot з таблиці вище, той самий
image05, `dm_count=0`, порожній список block mounts у всіх перевірених
namespaces. Значення `early_bootstrap_result`, `deploy_result`,
`root_task_probe_result` — усі `-11`.

Аудит завершеного final admission підтвердив повне читання RECOVERY/BOOT
з exact hashes і 87 installed source pins. Окремі completed
`UART-SRAM-OBSERVATION.json` у startup та final-idle каталогах підтверджують
qualified SRAM marker pairs і наступні kernel boots. Версія береться з
pinned `BOOT.json`: її literal у UART не друкується.

## Підсумкові докази

| Група | Шлях |
| --- | --- |
| Зведений public hardware result | `A/SESSION4-HARDWARE-RESULT.json` (`PASS_QUALIFIED_EVO16_PASSWORD_USER0`) |
| Build та audit образу | `A/image05/RESULT.json`; `A/root/build05/RESULT.json`; `A/review/image-audit04/RESULT.json` |
| Frozen harness/source pins | `A/root/cycle-controller03/FROZEN-PINS.json`; `VALIDATION.json`; `A/backend/hardware-cycle-source-pins05.json` |
| Основний auth/cycles/marker/close | `B/session-live03/AUTH.stdout`; `CYCLE-s4-*.outcome.json`; `MARKER-s4-*.outcome.json` |
| Fresh first_access / format authorization | `B/session-first-access02/AUTH-RESULT.json`; `B/session-format02-final/AUTH-RESULT.json` |
| Startup і policy restore | `B/session-startup01/STARTUP-PREPARED.json`; `AUTH.stdout`; `AUTH-RESULT.json`; `CYCLE-startup-*.outcome.json`; `POLICY-startup-06-policy-each-RESULT.json` |
| Аудит 56 completed receipts основної матриці | `A/review/session4-live01/{RESULT.json,REVIEW.md,EVIDENCE-PINS.json}` |
| Аудит 44 completed receipts startup/final | `A/review/session4-startup-final01/{RESULT.json,REVIEW.md,EVIDENCE-PINS.json}` |
| Фінальний idle | `B/session-final-idle03/{BOOT.json,FRESH-IDLE.json,UART-SRAM-OBSERVATION.json}` |

| Підсумковий запис | SHA-256 |
| --- | --- |
| `A/SESSION4-HARDWARE-RESULT.json` | `330f08441ad107bec1d84a9a202d8909f87676cb1e20743c18e15dbb7f738956` |
| `A/review/image-audit04/RESULT.json` | `b682372f444363888bfa8a8ce7cf812f9c29e88cc85b3e1673ce438665a3b94e` |
| `A/review/session4-live01/RESULT.json` | `bf69050ea7fe0b618cdf6784b538f94ef3019aae6c24af7d44d7241f0f47a330` |
| `A/review/session4-startup-final01/RESULT.json` | `f5c1acb2388562f9c68cc2721a513d70e81233804e9d9616721c9475084965a6` |
| `B/session-final-idle03/FRESH-IDLE.json` | `065422b5d8b3c0ae202b798a0cbae18ee0044ab860bda4d85755ca52ef5a7e2d` |

Історичні failed/attempt receipts збережені окремо; цей звіт їх не переписує
і використовує лише названі completed final-image докази. Контракти API:
[Reusable CE sessions](reusable-ce-session.md) і
[Format authorization](FORMAT_AUTHORIZATION.md).
