# Браузер рекавері: шлях кадру до ~90 FPS (2026-11-20)

Мета власника: близько 90 FPS стабільно під час перегляду сайтів. Попередні виміри на телефоні:
пряма Wayland-гілка з GPU 54,7 FPS (кадри від композитора, без справжнього UI), screencast 11,5 FPS.

## Шлях кадру до змін (1080×1620, 32 біти = 7,0 МБ)

1. Chromium (Ozone/Wayland, ANGLE → GLES на Panfrost) малює в linear dmabuf; композитор оголошує
   лише модифікатор LINEAR (`ui/web_dmabuf.h`, `dma_bind`).
2. `commit` → `publish_frame` (`ui/web_compositor.c`). `dma_read` питає fence через `poll(…, 0)`.
   GPU майже завжди ще працює в момент commit. Тоді кадр чекав наступного тіку таймера 90 Гц
   (`tick`), до 11,1 мс. Кадр, чия GPU-робота закінчилась одразу після тіку, пропускав цілий період.
   Кадри йшли то через 11, то через 22 мс, у середньому ~55 FPS. Це збігається з 54,7 FPS:
   той замір рахував кадри композитора з фальшивим UI, тож вузьке місце не в UI.
3. **Копія 1** (CPU): `memcpy` 7 МБ з dmabuf у слот memfd. Буфер Panfrost без когерентності
   CPU читає через write-combine, оцінка ~4–7 мс.
4. `F0`/`F1` з композитора йдуть Python-сесії (`web_session.py`, цикл `select`), вона пересилає їх
   у UI. `A0`/`A1` від UI повертаються тим самим шляхом. Це два переходи через Python на кадр, і
   вони конкурують із JSON CDP: дотики при прокрутці йдуть із частотою 90 Гц.
5. UI (`ui/web_ui.h`, `web_poll`) бере слот. **Копія 2**: `web_render_frame` копіює слот → `pixels`.
6. `present_web_page`: чекає vblank, потім **копія 3**: `pixels` → fb0 (запис у WC).

Разом 3 CPU-копії на кадр: ~21 МБ читання і ~21 МБ запису. При 90 FPS це ~3,8 ГБ/с пропускної
здатності LPDDR4X, яку ділимо з GPU.

## Що змінено

| Частина | Зміна |
|---|---|
| `ui/web_compositor.c`, `ui/web_dmabuf.h` | Буфер, який ще малюється, отримує спостерігач за його fence: `wl_event_loop_add_fd` на dmabuf, бо dma-buf стає readable, коли fence сигналить. Кадр копіюється одразу, без квантування тіком. Тік лишився запасним шляхом, frame callbacks так само щотіку (90 Гц). `dma_pending_fd` ставить спостерігач лише на справді незавершений fence (помилка `DMA_BUF_IOCTL_SYNC` не зациклює). |
| Те саме | Другий аргумент композитора — сокет кадрів UI (fd 6). `F`/`A` йдуть прямо в UI, без Python; control-сокет сесії лише стежить за завершенням. Без аргументу поведінка як раніше. |
| `ui/web_ui.h`, `ui/recovery_ui.c` | UI створює окремий SOCK_SEQPACKET для кадрів (fd 6 у дочірньому процесі), слухає його в `poll` і відповідає `A` туди, звідки прийшов кадр (`web_send_frames`). |
| Те саме | Кадр сторінки йде зі слоту одразу в панель (`present_web_slot`), без копії в `pixels`: на 7 МБ на кадр менше. `pixels` наздоганяє (`web_sync_pixels`) лише перед повним рендером, переходом (`transition_arm`) або знімком екрана. |
| `web_launch.py` | `reserve_frames_fd`: fd 6 лишається, лише якщо це AF_UNIX SEQPACKET; інакше туди ставиться `/dev/null`, щоб випадковий дескриптор не потрапив у простір браузера. `closerange` тепер з 7. Батьківський процес не тримає копію сокета. Перемикачі для вимірів: `/run/a22x-recovery/web-options.json` (лише root): `{"gpu_raster": false}`, `{"direct_frames": false}`. |
| `web_session.py` | Композитор отримує fd 6 (`A22X_WEB_FRAMES=1`). Старий композитор, що його не приймає, стартує вдруге без нього. Сесія закриває свою копію fd 6. З GPU додано `--ignore-gpu-blocklist --enable-gpu-rasterization`: тайли растеризує Mali, а не малі ядра A55. Без перемикача `A22X_WEB_RASTER=0` ці прапорці увімкнені. |
| `tools/web_fps.py` | Замір на телефоні: фальшивий UI, прокрутка «пальцем» 90 Гц, `--relay`, `--copy`. |
| `ui/test_web_compositor.c`, `make web-compositor-test` | Тест композитора на комп'ютері: Wayland-клієнт малює нумеровані кадри, фальшивий UI перевіряє слоти, підтвердження і відсутність кадрів на control-сокеті. |

## Бюджет на кадр після змін (оцінка)

- Композитор: копіювання починається з сигналом fence. Темп задає Chromium/GPU, а не тік 90 Гц,
  але не частіше за 90 Гц (`next_publish`).
- Python поза шляхом кадру, тож затримок від CDP-трафіку більше немає.
- UI: одна копія (слот → fb0) замість двох. Разом 2 CPU-копії на кадр: ~14 МБ читання і ~14 МБ
  запису, ~2,5 ГБ/с при 90 FPS (було ~3,8).
- Якщо Chromium тримав Panfrost у blocklist, GPU-растр знімає з CPU найважчу частину прокрутки.

## Перевірено на комп'ютері

- `cd ui && make test`: 115 самотестів UI, ok.
- `cd ui && make web-compositor-test` (x86, libwayland 1.26): direct 89,9 FPS і relay 90,0 FPS
  (180/180 кадрів за 2 с), 0 неправильних або розірваних кадрів, 0 повідомлень на control у прямому
  режимі. Шлях fence на комп'ютері не задіяний, бо SHM-буфери не мають fence.
- `pytest tests/test_web_*.py`: 42 пройдено, 3 пропущено (потрібен root або вільні fd 5/6).
- `tools/web_fps.py` на фальшивій сесії: 90,0 FPS у direct і relay.
- Базова збірка композитора з цього тулчейна байт у байт дорівнює попередньому бінарнику (3647a444…).

## Зібрані артефакти (aarch64)

- `$HOME/a22x-work/artifacts/browser-fps-20261120/web-compositor`:
  sha256 `623fe420208cbe1ca34dfd7e29f552648c4b797ca5ffddc464616e5806f406dc` (musl, libwayland-server;
  збірка `build-dmabuf.sh` з sysroot browser-direct).
- `$HOME/a22x-work/artifacts/browser-fps-20261120/a22x-recovery-ui-aarch64`:
  sha256 `1fc9ed940400197a029fbfae3564faba99bb076a2d23f110e7cb1a8b654e7726` (`make arm64`). У
  збірці образу UI збирається знову з вихідного коду.

## Як виміряти на телефоні

1. Образ: `tools/build_decrypt_image.py … --wayland-compositor
   $HOME/a22x-work/artifacts/browser-fps-20261120/web-compositor` (sha256 нижче); UI
   збирається `make arm64` (build.sh робить це сам).
2. Прошити рекавері, під'єднати Wi-Fi, дочекатися шарів рушія і GPU в RAM (`web_cache`).
3. Закрити браузер в UI. Потім:
   `adb push tools/web_fps.py /run/a22x-dev/` і
   `adb shell python3 -B /run/a22x-dev/web_fps.py --seconds 20 https://en.m.wikipedia.org/wiki/Linux`
   (очікується `"mode": "direct"`).
4. Порівняння: `--relay`; `--copy`; без GPU-растру:
   `echo '{"gpu_raster": false}' > /run/a22x-recovery/web-options.json` (потім видалити файл).
5. Справжній UI: відкрити браузер, прокрутити пальцем або `ui_finger.py swipe`. Якщо UI можна
   запустити з `A22X_RECOVERY_PROFILE_FRAMES=1`, рядки `[recovery-ui:frame-pacing]` у stderr дають
   інтервали показу.

## Не перевірено (тільки телефон покаже)

- Реальний FPS на телефоні з усіма змінами.
- Чи сигналить fence Panfrost через epoll на dma-buf саме на цьому ядрі: так роблять mutter і
  wlroots. Якщо ні, лишається запасний тік, тобто поведінка як раніше.
- Чи стабільні `--ignore-gpu-blocklist --enable-gpu-rasterization` на Mesa 26 / Panfrost.
  Артефакти малювання можливі, вимикач: `{"gpu_raster": false}`.
- Фактична швидкість читання WC-dmabuf (оцінка 4–7 мс за кадр).
- Шлях без GPU (screencast) не змінювався.
