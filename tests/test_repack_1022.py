"""Offline regression checks for the 1.0.2.2 native-display hotfix."""
import gzip
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "tools/repack_a22x_1022.py"
spec = importlib.util.spec_from_file_location("repack_a22x_1022", SOURCE)
repack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repack)


class NativeDisplayPackagerTests(unittest.TestCase):
    def test_version_change_preserves_uncompressed_cpio_bytes_elsewhere(self):
        data = b"070701fake-cpio\0" + repack.OLD_VERSION + b"\0TRAILER!!!\0"
        result = repack.update_ramdisk_version(gzip.compress(data, mtime=0))
        self.assertEqual(gzip.decompress(result), data.replace(repack.OLD_VERSION,
                                                              repack.NEW_VERSION))
        self.assertEqual(result[:4], bytes.fromhex("1f8b0800"))

    def test_version_patch_rejects_missing_or_duplicated_marker(self):
        for data in (b"1.0.2", repack.OLD_VERSION * 2, repack.NEW_VERSION):
            with self.subTest(data=data), self.assertRaises(ValueError):
                repack.update_ramdisk_version(gzip.compress(data, mtime=0))

    def native_properties(self):
        dsi = "/display-ml/dsi-ml@14013000"
        panel = dsi + "/panel@0"
        touch = "/spi1@11010000/novatek@0"
        return {
            ("/aliases", "dsi0"): dsi,
            ("/chosen/framebuffer@7c9b0000", "status"): "disabled",
            (panel, "compatible"): "jdi,hx83112f-a22x",
            (panel, "phandle"): "17d",
            (touch, "panel"): "17d",
            (touch, "compatible"): "novatek,NVT-ts-spi mediatek,7807s_touch "
                                    "focaltech,ft8722 himax,hx83112f himax,common",
            (touch, "touchscreen-size-x"): "1080",
            (touch, "touchscreen-size-y"): "2408",
        }

    def validate(self, props):
        def fdtget(_dtb, node, prop, typ="s"):
            return props[(node, prop)]

        with patch.object(repack, "fdt_property", side_effect=fdtget):
            return repack.validate_native_dtb(Path("test.dtb"))

    def test_native_panel_follower_and_four_touch_families(self):
        result = self.validate(self.native_properties())
        self.assertIn("novatek,NVT-ts-spi", result["touch_compatibles"])
        self.assertIn("himax,hx83112f", result["touch_compatibles"])

    def test_rejects_old_simpledrm_alias_and_missing_panel_follower(self):
        props = self.native_properties()
        props[("/aliases", "dsi0")] = "/dsi@14013000"
        with self.assertRaisesRegex(ValueError, "native MediaTek DSI"):
            self.validate(props)
        props = self.native_properties()
        props[("/spi1@11010000/novatek@0", "panel")] = "0"
        with self.assertRaisesRegex(ValueError, "follow its powered panel"):
            self.validate(props)

    def test_rejects_incomplete_novatek_or_ilitek_dtb(self):
        for omitted in ("novatek,NVT-ts-spi", "mediatek,7807s_touch",
                        "focaltech,ft8722", "himax,hx83112f"):
            props = self.native_properties()
            touch_key = ("/spi1@11010000/novatek@0", "compatible")
            props[touch_key] = props[touch_key].replace(omitted, "")
            with self.subTest(omitted=omitted), self.assertRaisesRegex(ValueError,
                                                                      "hardware variants"):
                self.validate(props)


if __name__ == "__main__":
    unittest.main()
