# Issue #1 — NT36675 SPI offline/QEMU audit (2026-11-19)

**Experimental source only. No physical Novatek A22x has run this driver.**
Passing this document's tests is not proof of panel power, firmware download,
IRQ polarity at the pin, or usable finger input on erayrafet's hardware.

## What is actually inside 1.0.2.x

The Linux 7.2 kernel used by the physical JDI test has
`CONFIG_TOUCHSCREEN_HIMAX_HX83112F=y` and
`CONFIG_TOUCHSCREEN_NT36XXX_SPI=y`. The Novatek driver registers the name
`sec_touchscreen`. The shared SPI node advertises Novatek, ILI7807S,
FocalTech FT8722 and Himax compatibles, **not four implemented drivers**.
ILI7807S and FT8722 Linux SPI ports are unfinished, so neither is supported.

The current ramdisk contains only these three runtime firmware files:
`Himax_firmware_fw_jdi.bin`, `Himax_firmware_fw_txd.bin`, and
`novatek_ts_fw.bin`. The production-test MP files exist on the owner's PC
but are not packed and are not normally needed to handle finger events.

Actual files, individually `gzip -9` compressed, not estimates:

| Firmware | Uncompressed bytes | gzip-9 bytes |
| --- | ---: | ---: |
| Himax JDI runtime | 131,072 | 39,999 |
| Himax TXD runtime | 131,072 | 39,917 |
| Novatek NT36675 runtime | 139,264 | 60,090 |
| **Three runtime files** | **401,408** | **140,006** |
| Himax JDI MP | 131,072 | 38,457 |
| Himax TXD MP | 131,072 | 38,654 |
| Novatek MP | 139,264 | 60,216 |
| **All six** | **802,816** | **277,333** |

The compiled Himax HX83112F ELF `.o` objects total 354,824 bytes (82,573
individually gzip-9-compressed); Novatek core+SPI total 46,864 bytes
(14,416 gzip-9). These are **object-file compression figures, not an exact
increment in linked `Image.gz`**. The entire current recovery kernel
`Image.gz` is 11,952,117 bytes, while the compressed recovery ramdisk is
29,362,634 bytes. No meaningful compressed size can yet be given for the
unported ILI7807S/FT8722 Linux drivers or their missing firmware.

## Evidence and source defects

- The reporter's OrangeFox trim ID `0c 00 00 72 66 03` matches the
  most specific `NT36675_IC` table entry with `hw_crc=2` and event buffer
  `0x22d00` in `nt36xxx_core.c`.
- The real stock `novatek_ts_fw.bin` SHA-256 is
  `6a75652cd36b48da932bad83624cd12505b6a536236ec83da9fd30dd116a2cb1`.
  The parser recognizes its 4 KiB-boundary `NVT` marker, firmware version
  `0x07` with inverted byte `0xf8`, 15 bounded segments (ILM, DLM and 13
  info sections), and a 131,072-byte upload region.
- The A22x firmware filename, 9.6 MHz SPI mode 0, 1080 × 2408 bounds,
  reset GPIO15 and IRQ GPIO14 are represented in the DTS/driver.
- **Four defensive source defects were found and patched:** missing
  `/chosen/bootargs` did not fail closed; the threaded IRQ request overrode
  DT's falling edge with rising edge; `devm_drm_panel_add_follower()` errors
  were ignored; a single ESD-like byte could trigger a firmware reload before
  checking the entire seven-byte watchdog prefix. The unused `press_id` and
  `finger_cnt` locals were removed; the ARM64 `nt36xxx_core.o` was rebuilt
  with `W=1` and **no warnings**.

## Emulation results and what they cover

| Test | Observation |
| --- | --- |
| 8 host `unittest` cases | Pass: valid/corrupted directory, trims, foreign bootargs, ESD full-frame check, page selection, dummy byte, source contract |
| Python model with real stock firmware | Pass: header, marker, version, 15 segments, SPI page sequence |
| x86_64 static C firmware model | Pass with real firmware |
| AArch64 statically linked C model via `qemu-aarch64` | Pass with the **same** real firmware and result |
| x86_64 ASan/UBSan C model | Pass; no diagnosed memory error in 4096 header mutations |
| AArch64 QEMU C model, 4096 mutations | Pass, without crashes |
| Actual Linux 7.2 NT36xxx source | Compiled with the aarch64 cross-compiler after the three fixes; **not run against a fake kernel SPI bus** |
| Physical SM-A226B Novatek / DSI / touch | **NOT TESTED** |

Reproduce locally with the proprietary firmware extracted from a compatible
stock device (not redistributed by this repository):

```fish
python3 -m unittest discover -s tests -p 'test_nt36675_emulation.py' -v
python3 tools/nt36675_emulator.py --firmware /path/to/novatek_ts_fw.bin \
    --nt36xxx-core /path/to/linux/drivers/input/touchscreen/nt36xxx_core.c
aarch64-linux-gnu-gcc -static -O2 -Wall -Wextra -Werror \
    -o /tmp/nt36675-emulator-arm64 tools/nt36675_firmware_emulator.c
qemu-aarch64 /tmp/nt36675-emulator-arm64 /path/to/novatek_ts_fw.bin
```

## A separate blocker: display panel variant

The physical 1.0.2.1 image mistakenly used `simpledrm`; the owner verified
both touch and short-Power blanking failed. Swapping **only the DTB** to
`mt6833-samsung-a22x-native-display.dtb` made Himax JDI touch work and native
MediaTek DRM handle screen blank/wake. The owner confirmed real touch on
2026-11-19. This native DTB currently hard-codes
`jdi,hx83112f-a22x` at `/display-ml/dsi-ml@14013000/panel@0`, and assigns
that panel as the shared touch node's follower.

**It is unsafe to promise this JDI image will also power the reporter's
Novatek/possibly Tianma or DJN display.** The wrong panel init sequence
may leave the screen black and the touch follower unprepared. A separate
board-panel DTB/driver or a carefully qualified simpledrm fallback is needed.
The OrangeFox Linux 4.14 vendor display init cannot just be swapped into
the native Linux 7.2 image.

## Physical Novatek acceptance gates before a stable release

1. Confirm LK-selected panel bootargs and native display compatibility.
   Never force the JDI native panel sequence onto an unidentified display.
2. After safe recovery-only flash, dmesg must show NT36675 trim and firmware
   CRC/programming success, `sec_touchscreen` in `/proc/bus/input/devices`,
   and **no Himax binding** to SPI0.0.
3. Capture real IRQ GPIO14 falling-edge counts and MT slots for touch-down,
   coordinates at each corner, continuous drag and 10-finger frames.
4. Repeat cold boot, screen blank/wake, suspend/resume and late firmware
   reload. Any firmware/IRQ failure must retain ADB recovery access.
5. Preserve the owner's original recovery backup; do not touch BOOT,
   userdata, modem or wipe requests. Test Android normal boot/BCB separately.

## Follow-up gate: Linux BOOT and installer APK

The owner also requested the driver in BOOT and an APK update **after**
Novatek operation is dependable. These are **not included or flashed here**.
The present `apk/build.sh` calls its `BOOT_IMG` the **Linux BOOT** image,
currently pinned by `catalog.json` to `Dodaskot/a22x-mainline` `v147` with
release `7.2.0-a22x+`. This is not permission to modify a stock Android BOOT.

Before making a new Linux BOOT and APK pair:

1. Pass the real NT36675 touchscreen, firmware, display/DSI and resume gates
   above. Establish which display-panel DTB works for the Novatek unit.
2. Port/enable the driver in the **matching Linux BOOT kernel source**, rebuild
   that specific kernel/boot image, verify boot image size, hardware device
   tree, Android/bootloader constraints and a safe recovery fallback. Do not
   transplant a recovery kernel blob into an unrelated Android BOOT image.
3. Update `catalog.json` only for a genuinely published Linux BOOT with a
   verified URL, version/release, size and SHA-256. The app rejects a BOOT
   image that does not match this catalog; its recovery download likewise
   must match the hash of the tagged recovery release.
4. Build the installer from **both exact verified images** using
   `RECOVERY_IMG`, `BOOT_IMG`, `RECOVERY_VERSION` and `BOOT_VERSION`, preserve
   the established APK signing key, and run its Java and Android smoke tests.
   Test SHA-256-checked downloads, recovery-only installation, the separate
   opt-in Linux BOOT path, backup/readback and recovery-to-Android reboot.
5. Publish the paired images/APK only after those checks. Neither QEMU success
   nor the owner's Himax JDI touch result meets the Novatek gate by itself.

The future larger recovery release is planned to add Android data decryption,
more complete backups and restore functionality; none of those features is
claimed by this 1.0.2.x compatibility hotfix.
