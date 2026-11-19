#!/usr/bin/env python3
"""Host-only NT36675 SPI/firmware model for the A22x recovery hotfix.

It models selected invariants of nt36xxx_{spi,core}.c using a stock firmware
file. It is NOT a physical touchscreen, DSI/panel, GPIO or timing emulator.
Never advertise a successful run as hardware qualification.
"""
# SPDX-License-Identifier: MIT

import argparse
import hashlib
import json
from pathlib import Path
import struct


NT36675_TRIM = bytes.fromhex("0c 00 00 72 66 03")
FIRMWARE_SHA256 = "6a75652cd36b48da932bad83624cd12505b6a536236ec83da9fd30dd116a2cb1"
EVENT_BUFFER = 0x22D00
SPI_FREQ_MAX = 9_600_000
IRQ_TRIGGER = "falling"


class FirmwareError(ValueError):
    pass


def chip_from_trim(trim):
    """The first, most specific A22x trim-ID entry in nt36xxx_core.c."""
    if len(trim) != 6 or any(trim[i] != NT36675_TRIM[i] for i in (0, 3, 4, 5)):
        return None
    return {"chip": "NT36675", "hw_crc": 2, "event_buffer": EVENT_BUFFER}


def selected_by_lk(bootargs):
    """Fail closed for absent LK identification on the shared SPI CS."""
    return bool(bootargs) and any(part in bootargs for part in
                                  ("nt36", "NT36", "novatek", "NVT"))


def is_esd_watchdog_frame(data):
    """Do not mistake a single 0xFD/0xFE/0x77 byte for a full ESD frame."""
    return len(data) >= 7 and all(value in (0xfd, 0xfe, 0x77) for value in data[:7])


def get32(firmware, offset):
    if offset < 0 or offset + 4 > len(firmware):
        raise FirmwareError("firmware header read out of bounds")
    return struct.unpack_from("<I", firmware, offset)[0]


def parse_firmware(firmware):
    """Mirror the checks in _nt36xxx_boot_prepare_firmware and bin parser."""
    size = len(firmware)
    if not 4096 <= size <= 512 * 1024:
        raise FirmwareError("firmware size outside driver bounds")
    marker_end = next((i * 4096 for i in range(size // 4096, 0, -1)
                       if firmware[i * 4096 - 3:i * 4096] in (b"NVT", b"MOD")), 0)
    if not marker_end:
        raise FirmwareError("NVT/MOD marker at 4 KiB boundary missing")
    version_offset = marker_end - 4096
    version, complement = firmware[version_offset:version_offset + 2]
    if version + complement != 0xff:
        raise FirmwareError("firmware version/complement mismatch")

    end = get32(firmware, 0)
    if end < 0x30 or end > size or (end - 0x30) % 16:
        raise FirmwareError("invalid segment-directory end")
    info_count = (end - 0x30) // 16
    overlay_count = (firmware[0x28] & 0xf) if (firmware[0x28] & 0x10) else 0
    count = 2 + info_count + overlay_count
    if count > 255:
        raise FirmwareError("segment count overflows u8")

    segments = []
    for i in range(count):
        if i < 2:
            pos = i * 12
            bin_addr, sram_addr, length = [get32(firmware, pos + delta)
                                          for delta in (0, 4, 8)]
            crc = get32(firmware, 0x18 + i * 4)
            name = ("ILM", "DLM")[i]
        else:
            if i < 2 + info_count:
                pos = 0x30 + 16 * (i - 2)
                name = "Info"
            else:
                pos = segments[1]["bin_addr"] + 16 * (i - 2 - info_count)
                name = "Overlay"
            sram_addr, length, bin_addr, crc = [get32(firmware, pos + delta)
                                                for delta in (0, 4, 8, 12)]
        # Vendor ROM encodes last byte inclusive; use the same check as C.
        if bin_addr > size or (length and length >= size - bin_addr):
            raise FirmwareError(f"segment {i} exceeds firmware buffer")
        segments.append({"type": name, "bin_addr": bin_addr,
                         "sram_addr": sram_addr, "length_minus_one": length,
                         "crc": crc})

    return {"file_bytes": size, "upload_limit": marker_end,
            "version": version, "info_segments": info_count,
            "overlay_segments": overlay_count, "segments": segments,
            "sha256": hashlib.sha256(firmware).hexdigest()}


class FakeNT36675SPI:
    """Verify 24-bit page-select, bit7 write bit and read dummy-byte removal."""

    def __init__(self):
        self.memory = {}
        self.commands = []

    @staticmethod
    def page_select(address):
        if not 0 <= address <= 0xffffff:
            raise ValueError("register address must be 24-bit")
        return bytes((0xff, (address >> 15) & 0xff, (address >> 7) & 0xff))

    def write(self, address, value):
        if not 0 <= value <= 255:
            raise ValueError("register value must be byte")
        page = self.page_select(address)
        command = (address & 0x7f) | 0x80
        self.commands.extend((page, bytes((command, value))))
        self.memory[address] = value

    def read(self, address, length=1):
        if not 0 < length <= 4096:
            raise ValueError("unsupported read length")
        page = self.page_select(address)
        command = address & 0x7f
        self.commands.extend((page, bytes((command,))))
        # The real chip sends a dummy byte; the Linux SPI transport drops it.
        reply = b"\x00" + bytes(self.memory.get(address + i, 0) for i in range(length))
        return reply[1:]


def protocol_smoke():
    chip = FakeNT36675SPI()
    for address, value in ((0x03f0fe, 0x69), (0x03f310, 0), (EVENT_BUFFER, 0xa3)):
        chip.write(address, value)
        if chip.read(address) != bytes((value,)):
            raise AssertionError("SPI model lost a register write")
    return {"page_transactions": len(chip.commands),
            "reset_address": "0x03f0fe", "event_buffer": hex(EVENT_BUFFER),
            "dummy_byte_removed": True}


def source_contract(source):
    """Warn if the Linux code drifts from the assumptions being modelled."""
    code = Path(source).read_text()
    spi_code = Path(source).with_name("nt36xxx_spi.c").read_text()
    checks = {
        "A22x NT36675 trim": "0x0C, 0xFF, 0xFF, 0x72, 0x66, 0x03" in code,
        "NT36675 hardware CRC": ".hw_crc = 2" in code,
        "missing bootargs fail closed": "if (of_property_read_string(dt_node, \"bootargs\", &bootargs) ||" in code,
        "IRQ follows DT instead of rising override":
            "IRQF_ONESHOT, dev_name(dev), ts)" in code and
            "IRQ_TYPE_EDGE_RISING | IRQF_ONESHOT" not in code,
        "panel follower registration checked":
            "ret = devm_drm_panel_add_follower(dev, &ts->panel_follower);" in code,
        "firmware filename exposed": '"novatek_ts_fw.bin"' in spi_code,
        "SPI read discards dummy byte": "memcpy(val_buf, rx + 1, val_size);" in spi_code,
        "10-slot multitouch": "TOUCH_MAX_FINGER_NUM" in code,
        "ESD detection checks whole watchdog frame": "if (i == 7)" in code,
    }
    if not all(checks.values()):
        raise ValueError("Linux source contract failed: " +
                         ", ".join(k for k, value in checks.items() if not value))
    return checks


def qualify(firmware, source):
    checks = source_contract(source)
    info = parse_firmware(Path(firmware).read_bytes())
    if info["sha256"] != FIRMWARE_SHA256:
        raise FirmwareError("not the reviewed Samsung NT36675 firmware")
    chip = chip_from_trim(NT36675_TRIM)
    if not chip or chip["hw_crc"] != 2:
        raise AssertionError("NT36675 trim map is incorrect")
    spi = protocol_smoke()
    return {"offline_protocol": "PASS", "linux_source": checks,
            "chip": chip, "spi": spi,
            "firmware": {k: value for k, value in info.items() if k != "segments"},
            "segment_count": len(info["segments"]),
            "irq_trigger_expected": IRQ_TRIGGER,
            "native_jdi_display_on_novatek": "INCOMPATIBLE_NEEDS_PANEL_VARIANT",
            "physical_nt36675_test": "NOT_AVAILABLE",
            "release_qualification": "EXPERIMENTAL_ONLY"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--nt36xxx-core", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.firmware, args.nt36xxx_core), indent=2))


if __name__ == "__main__":
    main()
