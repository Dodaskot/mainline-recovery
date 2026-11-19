# SM-A226B recovery 1.0.2.1 — first physical boot report, 2026-11-19

**Status: boot/driver/UI smoke passed; physical touch not yet verified.**

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

1. Have the owner touch the live screen while logging `/dev/input/event2`
   and IRQ 29; check tap, drag, corners and multitouch in the actual UI.
2. Verify the refined SPI selector on Novatek and an Ilitek Tianma variant,
   not only on the present Himax JDI device.
3. Test a real **Novatek NT36675** A22x revision; check firmware load and
   `sec_touchscreen`/evdev input, coordinate geometry and multi-touch.
4. Independently test Ilitek ILI7807S, FocalTech FT8722 and Himax TXD once
   their appropriate Linux 7.2 drivers and firmware are ready.
5. Only after the refined 1.0.2.1 image meets the requested real-touch gate, install and
   smoke-test `1.1.0-dev-device-feedback.28`; do not equate the newest image
   with a stable release, and preserve the original `.25` backup.
6. Do not claim normal Android boot/BCB loop fixed without an actual Android
   reboot and bootloader evidence. Android Data remains locked.
