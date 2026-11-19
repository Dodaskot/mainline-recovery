"""NT36675 offline SPI/firmware negative tests (NOT real hardware)."""
import importlib.util
import os
from pathlib import Path
import struct
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "tools/nt36675_emulator.py"
spec = importlib.util.spec_from_file_location("nt36675_emulator", SOURCE)
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


def synthetic_firmware():
    data = bytearray(8192)
    # The first u32 is both ILM's bin address and the directory-end field.
    struct.pack_into("<III", data, 0, 0x30, 0, 0x20)  # no extra info sections
    struct.pack_into("<III", data, 12, 0x100, 0x1000, 0x20)  # DLM
    data[4096] = 0x07
    data[4097] = 0xf8
    data[8192 - 3:8192] = b"NVT"
    return data


class NT36675FirmwareTests(unittest.TestCase):
    def test_valid_image_directory_and_marker(self):
        result = model.parse_firmware(synthetic_firmware())
        self.assertEqual(result["version"], 7)
        self.assertEqual(result["upload_limit"], 8192)
        self.assertEqual([segment["type"] for segment in result["segments"]],
                         ["ILM", "DLM"])

    def test_rejects_bad_header_marker_version_and_bounds(self):
        variants = []
        source = synthetic_firmware()
        mutation = bytearray(source)
        mutation[8192 - 3:] = b"BAD"
        variants.append(mutation)
        mutation = bytearray(source)
        mutation[4097] = 0
        variants.append(mutation)
        mutation = bytearray(source)
        struct.pack_into("<I", mutation, 0, 0x31)
        variants.append(mutation)
        mutation = bytearray(source)
        struct.pack_into("<I", mutation, 8, 0xffff)
        variants.append(mutation)
        variants.extend((source[:512], bytearray(513 * 1024)))
        for variant in variants:
            with self.subTest(length=len(variant), prefix=bytes(variant[:4])), \
                    self.assertRaises(model.FirmwareError):
                model.parse_firmware(variant)

    def test_rejects_oversized_overlay_table(self):
        data = synthetic_firmware()
        data[0x28] = 0x1f  # 15 overlay records
        # DLM's bin address points beyond the firmware for overlay headers.
        struct.pack_into("<I", data, 12, 8191)
        with self.assertRaises(model.FirmwareError):
            model.parse_firmware(data)

    def test_reporter_trim_and_foreign_controllers(self):
        self.assertEqual(model.chip_from_trim(bytes.fromhex("0c 00 00 72 66 03"))["hw_crc"], 2)
        self.assertIsNone(model.chip_from_trim(bytes.fromhex("0a 00 00 72 66 03")))
        self.assertIsNone(model.chip_from_trim(b"\x00" * 6))

    def test_bootargs_fail_closed_and_no_tianma_false_positive(self):
        for name in (None, "", "hx83112f_fhdp_jdi", "ili7807_tianma",
                     "focaltech_ft8722_truly", "tianma"):
            self.assertFalse(model.selected_by_lk(name), name)
        for name in ("nt36672c_fhdp_tianma", "novatek_nt36675_djn", "NVT-ts-spi"):
            self.assertTrue(model.selected_by_lk(name), name)

    def test_esd_watchdog_requires_entire_frame(self):
        for sequence in (b"\xfd" * 7, b"\xfe" * 7, b"\x77" * 7,
                         bytes.fromhex("fd fe 77 fd fe 77 fd")):
            self.assertTrue(model.is_esd_watchdog_frame(sequence))
        for sequence in (b"\xfd", b"\xfd" + b"\x00" * 6,
                         b"\x77" * 6 + b"\x01"):
            self.assertFalse(model.is_esd_watchdog_frame(sequence))

    def test_spi_address_page_select_read_dummy_and_errors(self):
        state = model.FakeNT36675SPI()
        self.assertEqual(state.page_select(0x3f0fe), bytes.fromhex("ff 07 e1"))
        self.assertTrue(model.protocol_smoke()["dummy_byte_removed"])
        state.write(0x22d00, 0xa3)
        self.assertEqual(state.read(0x22d00), b"\xa3")
        for address in (-1, 0x1000000):
            with self.assertRaises(ValueError):
                state.read(address)

    def test_linux_source_stays_in_sync_with_model(self):
        source = os.environ.get("A22X_NT36XXX_SOURCE")
        if not source:
            source = SOURCE.parents[2] / "linux-a22x-audit/drivers/input/touchscreen/nt36xxx_core.c"
        if not Path(source).exists():
            self.skipTest("set A22X_NT36XXX_SOURCE for the Linux source contract")
        checks = model.source_contract(source)
        self.assertTrue(all(checks.values()))


if __name__ == "__main__":
    unittest.main()
