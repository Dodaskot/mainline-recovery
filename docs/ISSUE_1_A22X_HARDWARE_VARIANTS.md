# SM-A226B hardware variants and issue #1 — 1.0.2.x compatibility audit

This audit concerns the **1.0.2** recovery branch, not the later experimental
development builds. Do not describe untested touchscreen drivers as supported.

Evidence:

- Report and OrangeFox kernel log: https://github.com/Dodaskot/mainline-recovery/issues/1
- Reporter device tree, branch `test`: https://github.com/erayrafet/ofox_device_samsung_a22x/tree/test
- Samsung SM-A226B vendor kernel: `drivers/input/touchscreen/mediatek/NT36672C/`
- Recovery kernel: https://github.com/Dodaskot/linux-a22x, `a22x-recovery`, commit
  `7db22ea862aba94d93561f0aef18bb8df21cd888`.
- Known-good baseline recovery v1.0.2 SHA-256:
  `86202777e38c5cf0ace0282f3defdd30832fae83d694edc6b2658a4cd7f28c7f`.
- Physical Himax and native-display follow-up:
  `docs/ISSUE_1_A22X_LIVE_TEST_20261119.md`.
- Actual NT36675 firmware parser, QEMU ARM64, sanitizer and negative results:
  `docs/ISSUE_1_NOVATEK_OFFLINE_AUDIT_20261119.md`.

## Hardware, not just firmware

The single stock SPI1 child `novatek@0` in the reporter's prebuilt `dtbo.img`
advertises all four compatible strings, in this order:

1. `novatek,NVT-ts-spi` (Novatek)
2. `mediatek,7807s_touch` (Ilitek ILI7807S)
3. `focaltech,ft8722` (FocalTech)
4. `himax,common` (Himax HX83112F)

The overlay also lists Tianma and DJN Novatek panels, TXD ILI7807S, Truly
FT8722, TXD and JDI Himax panels, plus a virtual fallback panel. The LK
framebuffer may already be initialized by the bootloader; this **does not**
imply the matching touchscreen is initialized by the recovery kernel.

For Novatek, the overlay contains:

| Property | Value |
| --- | --- |
| Bus | SPI1, chip select 0, 9,600,000 Hz, mode 0 in the reporter's log |
| Reset / IRQ | MT6833 GPIO15 / GPIO14 (the vendor log's `316` is *not* Linux GPIO316) |
| `novatek,swrst-n8-addr` | `0x03f0fe` |
| `novatek,spi-rd-fast-addr` | `0x03f310` |
| `novatek,resolution` | `1080, 2408` |
| `novatek,max_touch_num` | 10 |
| Firmware | `novatek_ts_fw.bin`, `novatek_ts_mp.bin` |

**Identification:** the reporter's trim bytes `0c 00 00 72 66 03` match
`NT36675_memory_map` in the Samsung vendor kernel's `nt36xxx_mem_map.h`.
They do **not** match the `NT36672A` entry. A general NT36672A-only SPI driver
uses the wrong event-buffer and firmware-register map unless extended for
NT36675. The panel may still be advertised as `nt36672c` by the display stack.

The v1.0.2 kernel has only the Himax HX83112F SPI driver, its DTS explicitly
lists only Himax compatibles, and the published ramdisk has only the JDI Himax
runtime firmware. Enabling `CONFIG_TOUCHSCREEN_NOVATEK_NVT_TS` will not help:
that mainline driver is for **I2C**. The vendor SPI drivers need porting and
**successful chip identification before claiming the shared SPI node**.

Known firmware files on the owner's Arch Linux PC (TWRP source package):

| Filename | Bytes | SHA-256 |
| --- | ---: | --- |
| `Himax_firmware_fw_jdi.bin` | 131072 | `fd4df971965dfe5e550ba4a6a9e94e1b67d5ca128dad3eb74ebaa1873d591f1a` |
| `Himax_firmware_mp_jdi.bin` | 131072 | `548b040f6262d0a0599660eef7883894a52a5ccf0ccbdfee186c5d27ec5feceb` |
| `novatek_ts_fw.bin` | 139264 | `6a75652cd36b48da932bad83624cd12505b6a536236ec83da9fd30dd116a2cb1` |
| `novatek_ts_mp.bin` | 139264 | `63f5c8e172f34167fce8845c5f29648b01d9e428c53295ece51ad6fba2940c87` |

The reporter's OrangeFox prebuilt also has `Himax_firmware_fw_txd.bin` and
`Himax_firmware_mp_txd.bin` and many generic Goodix firmware files. The JDI
Himax firmware in that tree has a *different* hash from the v1.0.2/TWRP file;
do not overwrite an already qualified firmware merely because the name matches.
MP firmware is used for production tests, not a substitute for runtime firmware.

## Boot and partition compatibility

The OrangeFox tree supplies a **Linux 4.14.358-openela-H3CKED** kernel
(verified from its `prebuilt/Image.gz`) and stock-style DTB/DTBO.
Its image format is Android boot header v2, 2 KiB pages, separate recovery
partition of 40 MiB, `misc` for recovery requests, `metadata` as ext4 and
`userdata` as F2FS. Its `TW_INCLUDE_CRYPTO`, `TW_INCLUDE_CRYPTO_FBE`, and
`TW_INCLUDE_FBE_METADATA_DECRYPT` are **false**. Do not infer working data
decryption from the device tree. Preserve the 1.0.2 mainline Linux 7.2 kernel,
original ABI/DTB geometry, and boot image checks while porting the touch
drivers; swapping in stock OrangeFox `Image.gz` is not a compatible fix.

## Staged Linux 7.2 touch adaptation

The separate `linux-a22x` experimental hotfix branch adds an SPI NT36xxx
transport derived from George Chan's mainline-oriented RFC and the matching
**NT36675** trim ID, event buffer, hardware-CRC firmware download and
`novatek_ts_fw.bin` name. It also keeps the known-good Himax HX83112F path.
The shared SPI chip-select permits only one bound driver, so a driver must
**return `-ENODEV` for an identified foreign panel** rather than registering
successfully and blocking the matching controller. The Novatek port gates
probing on the LK-selected panel string; Himax explicitly skips known
Novatek/Ilitek/FocalTech panels. Missing or ambiguous bootargs are not proof
of controller identity, so hardware tests remain compulsory.

A follow-up review found that checking `tianma` alone is insufficient: this
names a display *vendor*, not a Novatek chip, and an Ilitek variant may also
use Tianma. The revised **kernel source** requires an explicit
`nt36`/`NT36`/`novatek`/`NVT` chip-family marker and fills out SPI aliases.
The first on-device 1.0.2.1 image predates these refinements. The rebuilt
revision was subsequently flashed and booted as kernel `#3` on Himax JDI,
with the missing-SPI-ID warnings gone. The owner reported real touch and
short-Power blanking **failed** on that simpledrm DTB. A later DTB-only
native-display prototype bound Himax after panel preparation; the owner
confirmed real finger input and the display service blank/wake path succeeded.
The correctly versioned 1.0.2.2 image is still an offline candidate, while
Novatek hardware qualification is still pending.

The NT36675 source then received four additional safeguards: fail closed
when LK `/chosen/bootargs` is missing, preserve the devicetree's falling-edge
touch IRQ rather than force rising-edge, and check DRM panel-follower
registration, and require the complete seven-byte watchdog marker before
firmware recovery. The patched ARM64 object compiled with W=1 and no warnings.
A host Python model, x86
ASan/UBSan and static AArch64 QEMU C model validated the owner's actual
139,264-byte firmware plus 4096 deterministic corruptions. **These source
changes are not yet in the physically tested kernel image.** The JDI-only
native-display panel is a separate blocker on Novatek/Tianma hardware; a
Novatek-compatible panel DTB or qualified LK simpledrm fallback is required.

Himax's already-qualified JDI firmware stays the default. When LK bootargs
explicitly identify a TXD HX83112F panel, the SPI glue selects
`Himax_firmware_fw_txd.bin`/`Himax_firmware_mp_txd.bin` and the corresponding
vendor panel name. This path still needs a real TXD device test.

Ilitek ILI7807S and FocalTech FT8722 require separate SPI and host-download
ports. Their vendor MediaTek `tpd` implementations cannot be linked directly
against Linux 7.2. A 2026 upstream FT8722 SPI patch series exists, but its
firmware and protocol must be verified for the A22x Truly variant. Neither
controller is supported just because its compatible occurs in the DTBO.

Rebooting from the Android installer uses `reboot recovery`. At recovery start,
`bcb.py arrive` normally clears a plain `boot-recovery`; intentional Android
wipe requests must remain. A normal reboot uses the kernel restart target
`normal`, followed by the board-specific LK restart policy. On this board,
preloader SRAM markers can also be lost during a double restart, which the
`restart_intent.py` **one-shot** mechanism attempts to mitigate. These are
independent mechanisms; the reporter supplied no `misc` dump, previous boot
log, BOOT partition identity, or recovery-specific log to prove which failed.
Do not erase a wipe request to conceal a failed Android boot.

## Regression/acceptance matrix — device tests still required

| Variant | Probe and firmware | Touch/UI | Restart and safety |
| --- | --- | --- | --- |
| Himax JDI (existing device) | `himax-touchscreen`, original qualified JDI firmware, no Novatek binding | 10-point MT, correct 1080×2408 coordinates; cold boot and late evdev | Recovery → Android, recovery again; unchanged BOOT and BCB wipe request |
| Himax TXD | Select TXD firmware by **proven panel identity**, no blind JDI fallback | First touch, corners, multi-touch, resume | Same reboot cases |
| Novatek (reporter, trim `0c 00 00 72 66 03`) | NT36675 memory map, SPI0 mode, 9.6 MHz, firmware checksum/host download, `sec_touchscreen` | First touch, all corners, 10 slots, cold boot and suspend | Same reboot cases; previous boot `pstore` if returns to recovery |
| ILI7807S TXD | Chip/panel match, vendor protocol and firmware verified | First touch, corners, resume | Same reboot cases |
| FocalTech FT8722 Truly | Chip/panel match, host-download firmware verified | First touch, corners, resume | Same reboot cases |

On an Ilitek Tianma panel, ensure the Novatek SPI driver does **not** claim
the shared chip-select or start a firmware download. Likewise, Himax must
decline known Novatek/Ilitek/FocalTech hardware.

Additional checks on *each* hardware revision:

- Kernel boots with the same original 1.0.2 boot image geometry and board ID;
  framebuffer remains visible even when the touch chip is absent/unrecognized.
- Verify actual `/proc/device-tree/.../compatible` **after LK DTBO merge**, SPI
  probe failures, `/sys/class/input/event*/device/name`, and `/dev/input` hotplug.
- F2FS userdata, ext4 metadata and cache, logical `system/vendor/product/odm`
  partitions, read-only EROFS images, and access to internal storage and SD/USB.
- `bcb.py prepare-normal`: stale plain `boot-recovery` clears; `--wipe_data` or
  `--prompt_and_wipe_data` remains untouched and normal reboot is explicitly
  refused; truncated/unreadable `misc` is refused, never assumed empty.
- Android BOOT was not inadvertently replaced by the installer; collect
  `/proc/last_kmsg` or `/sys/fs/pstore/*` and LK/preloader diagnostics if a
  normal reboot still enters recovery. One-shot restart must not loop.

Tests that can run without the phone:

```fish
python3 -m unittest discover -s tests -p 'test_bcb.py' -v
python3 -m unittest discover -s tests -p 'test_touch_variants.py' -v
python3 -m unittest discover -s tests -p 'test_restart_intent.py' -v
make -C ui input-rescan-test touch-input-test
```

## Release notes wording (when the hotfix has passed device tests)

**Recovery 1.0.2.2 — experimental compatibility hotfix (based on 1.0.2).** Better
touch-controller discovery for the Samsung Galaxy A22 5G, guarded handling
of recovery reboot requests, correct native MediaTek DSI/Himax JDI panel
timing, and documented SPI hardware variants.
**Important:** only claim a particular controller is supported after it has
passed a real-device probe and touch test. A much larger recovery update is
planned, including full Android data decryption and improved backups/restores;
those features are **not included or guaranteed** in this 1.0.2.x hotfix.
