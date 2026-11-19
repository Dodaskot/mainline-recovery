# SM-A226B recovery 1.0.2.x — physical touch/display tests, 2026-11-19

**Status: 1.0.2.1 physically FAILED touch and Power blanking. The DTB-only
1.0.2.2 prototype physically booted with native DRM, and the owner explicitly
confirmed finger touch works. Display blank/wake passed in UI logs.**

This report records what was observed on the connected owner's **SM-A226B**
with an LK-selected JDI `hx83112f_fhdp_wt_dsi_vdo_cphy_90hz_jdi` panel.
It does not establish support for a different A22x touchscreen variant.

- The original recovery `.25` partition contents were backed up and SHA-256
  verified on the owner's Arch Linux PC before flashing.
- A 40 MiB recovery image assembled from the original v1.0.2 Android v2
  header/DTBO and a Linux 7.2 touch-enabled kernel was written **only** to the
  dedicated `recovery` partition. The read-back SHA-256 matched the image:
  `cebfdd1acb85bf156b78bde153b8eb2de53780d2534d8aecc4b00397434898ed`.
- The first `adb reboot recovery` returned successfully but **did not reboot**
  the custom recovery. This was detected using uptime and the *top-level*
  version field (a text search accidentally matched historical metadata).
- The existing recovery's guarded power helper refused a restart with a
  mounted microSD card. The standard filesystem/storage helpers cleanly
  unmounted `userdata` and `sdcard-p1`; the power preflight then reported
  `POWER_PREFLIGHT_OK`. `/bin/recovery-power recovery` really rebooted.
- The new boot reported Linux `7.2.0-a22x-recovery+` `#2`, top-level
  recovery version `1.0.2.1`, and a fresh uptime.
- Kernel reported `HX83112F touch ready, irq 29`; `himax-touchscreen` appeared
  at `/dev/input/event2`, bound through `himax-hx83112f` despite the shared
  SPI device's `spi:NVT-ts-spi` modalias. The recovery UI and display service
  were both running; fb0 reported 1080 × 2408.
- Read-only BCB examination returned empty `command` and `recovery` fields,
  `wipe=false`.
- During 35 seconds of **real** evdev monitoring, there were zero input
  events and the Himax IRQ counter stayed at 1. No one has confirmed touching
  the physical screen during that interval; this is **inconclusive**, neither
  a touch pass nor evidence of a defect.
- The kernel logged warnings about missing `spi_device_id` entries for
  shared-device compatibles; revised kernel source has added aliases. It also
  refines the Novatek selector to avoid an Ilitek Tianma false-positive.

## Revised 1.0.2.1 SPI-selector image: second physical boot

- The original 1.0.2.1 image was unpacked, rebuilt and AVB-refooted **byte for
  byte identically** before any new packaging was attempted.
- The refined Linux 7.2 `Image.gz` compiled successfully with the SPI aliases
  and narrower Novatek hardware selection. Repacking changed **only** the
  kernel boot payload; ramdisk, DTB and recovery-DTBO compared byte-identical.
- AVB footer and recovery hash verified on the new 40 MiB image.
- A second recovery flash was limited to `/dev/mmcblk0p42`; full readback
  matched SHA-256:
  `1d02e43afb2498698400ded11bcd841d16cfb9f83026294bca883123d0eb7367`.
- The recovery's guarded helper rebooted into Linux
  `7.2.0-a22x-recovery+ #3`, reporting top-level recovery version `1.0.2.1`.
  The Himax driver again reported `HX83112F touch ready, irq 29`, and
  `himax-touchscreen` appeared at event2. Its driver owned shared SPI0.0;
  the UI/display service ran; BCB remained empty and `wipe=false`.
- The previous `has no spi_device_id` warnings were **absent**.
- **Still no real finger-event pass**. A second 35-second capture on the
  refined kernel `#3` produced zero evdev events; IRQ 29 remained at 1
  before and after. Physical screen contact was not confirmed in that window,
  so this remains **inconclusive**, not an observed touch failure.

## Physical failure report and root-cause candidate

The owner subsequently touched the live 1.0.2.1 screen and confirmed that
**touch did not operate**. A short Power press did not blank the screen,
although holding Power still worked. During the owner's touch attempts, IRQ
29 increased from 2810 to 4360. A read-only capture showed Himax MT pressure,
width and slot events; an MT-slots ioctl also contained previous coordinate
values, so it is incorrect to say all coordinate events were absent.

1.0.2.1 had packaged the **basic**
`mt6833-samsung-a22x.dtb`, exposing `simpledrm` but no native DSI panel
follower. `/opt/a22x-recovery/display.py status` reported `supported=false`,
`brightness_supported=false` and `blank_supported=false`; the UI logged
display-control exit=2. `himax-hx83112f` registered at ~0.48 s **without**
waiting for the JDI panel. Its runtime JDI firmware matched the earlier `.25`
backup byte-for-byte; an on-device self-test failed, but that is not a valid
runtime touch diagnosis because the MP test firmware was absent.

The `.25` backup, in contrast, contains a native MediaTek display FDT inside
a DT_TABLE wrapper with `/display-ml/dsi-ml@14013000/panel@0` and a `panel`
phandle on the shared SPI touch child. The Linux 7.2 source already built the
matching opt-in `mt6833-samsung-a22x-native-display.dtb` (DRM and the relevant
panel drivers all `=y`). The 1.0.2.1 image had selected the wrong built DTB,
not omitted a missing Linux touchscreen driver for this particular Himax JDI.

## Native-display prototype (1.0.2.2 packaging test)

- Starting from the installed SPI-guard 1.0.2.1 image, `mkbootimg` + AVB
  reproduced that original 40 MiB image **byte-for-byte**, SHA-256
  `1d02e43afb2498698400ded11bcd841d16cfb9f83026294bca883123d0eb7367`.
- Repacked **only** the compiled native-display DTB (SHA-256
  `c3da8e29cd0ef2f9bd2f5974ebbd15f59dc11be555397e62a60dd4f7084e62c6`).
  The kernel, ramdisk and recovery DTBO were identical. AVB verified.
- Flashed only `/dev/mmcblk0p42`, checked a full 40 MiB readback SHA-256
  `cb3fb124067721b635949f72920995668e99243e74443d6203ce5fb3e7df85fc`;
  the original `.25` backup remains available. This prototype's unchanged
  ramdisk still reports `1.0.2.1` in `build.json`; do not represent it as a
  fully versioned public 1.0.2.2 release.
- Rebooted using the guarded power helper after `POWER_PREFLIGHT_OK`. At
  startup dmesg recorded `Initialized mediatek`,
  `HX83112F touch ready after panel power-on`, and
  `fb0: mediatekdrmfb frame buffer device`.
- The UI opened `himax-touchscreen` at `/dev/input/event3` (MT, 1080 × 2408).
  Display status now returns `supported=true`, 60/90 Hz,
  `brightness_supported=true`, `blank_supported=true`. The UI logged a
  successful short-Power `toggle` to `blanked=1` followed by `wake` to
  `blanked=0`. The touch IRQ counter increased from 1 to 842, and UI page
  transitions were recorded. The owner subsequently **confirmed the physical
  screen now responds to touch**; a later 25-second passive evdev capture
  occurred without further events, which does not contradict that report.
- A separate offline packager now enforces the native DSI alias, disabled
  simple-framebuffer, powered panel phandle, all four shared-SPI compatible
  strings, and 1080 × 2408 geometry. It changes the single same-length
  `build.json` version field to `1.0.2.2` without disturbing the rest of the
  newc archive. Actual compiled firmware and the other hardware variants
  remain subject to separate real-device qualification.
- Its correctly versioned, **offline-only** 1.0.2.2 image (same kernel and
  native DTB, with exactly one same-length `build.json` version change in the
  ramdisk) passed full payload round-trip and AVB verification, SHA-256
  `0c5709c7f35c080f776f1b9b8c7ce1180e1f1b570a328ea5d5bb02fd171a0d02`.
  This new versioned image has **not** replaced the physically tested DTB-only
  prototype on the device yet.

## Read-only Android BOOT versus Recovery check

On this owner's device, BOOT is `/dev/mmcblk0p41` (32 MiB) and dedicated
Recovery is `/dev/mmcblk0p42` (40 MiB). Their full SHA-256 hashes differ:

- BOOT: `b16d551fbb23e8cf277c0a9cdc7e1a4fa7abf2b30e5d584911046dc451c27228`
- Recovery: `1d02e43afb2498698400ded11bcd841d16cfb9f83026294bca883123d0eb7367`

BOOT starts with the Android boot magic `ANDROID!`. This **rules out a literal
copy** of the tested recovery image into BOOT on the owner's current phone,
but does not prove the Android kernel/init are bootable or explain the
reporter's separate recovery-return symptom. No BOOT or BCB data was altered.

## Unfinished gates

1. The owner confirmed real finger navigation on the native-display prototype.
   Still repeat systematic corners, drags, 10-finger multitouch and resume
   on Himax JDI; a casual touch pass does not certify all gestures.
2. Verify the refined SPI selector on Novatek and an Ilitek Tianma variant,
   not only on the present Himax JDI device.
3. Test a real **Novatek NT36675** A22x revision; check firmware load and
   `sec_touchscreen`/evdev input, coordinate geometry and multi-touch.
4. Independently test Ilitek ILI7807S, FocalTech FT8722 and Himax TXD once
   their appropriate Linux 7.2 drivers and firmware are ready.
5. Only after the native 1.0.2.2 candidate meets the requested real-touch gate, install and
   smoke-test `1.1.0-dev-device-feedback.28`; do not equate the newest image
   with a stable release, and preserve the original `.25` backup.
6. Do not claim normal Android boot/BCB loop fixed without an actual Android
   reboot and bootloader evidence. Android Data remains locked.
