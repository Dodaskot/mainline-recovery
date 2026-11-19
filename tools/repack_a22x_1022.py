#!/usr/bin/env python3
"""Offline-only A22x recovery 1.0.2.2 native-display qualification/repack.

This deliberately starts from the physically tested 1.0.2.1 image.  It only
changes the DTB and the same-length version field in the initramfs manifest.
It never invokes adb or writes a block device.
"""
# SPDX-License-Identifier: MIT

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


PARTITION_SIZE = 41_943_040
BASE_SHA256 = "1d02e43afb2498698400ded11bcd841d16cfb9f83026294bca883123d0eb7367"
NATIVE_DTB_SHA256 = "c3da8e29cd0ef2f9bd2f5974ebbd15f59dc11be555397e62a60dd4f7084e62c6"
AVB_SALT = "88529080c91c96032c38f6769f5efac130561988dfb3ff3c96a14e5b36891dbb"
OLD_VERSION = b'"version": "1.0.2.1"'
NEW_VERSION = b'"version": "1.0.2.2"'
CMDLINE = (
    "bootopt=64S3,32N2,64N2 earlycon=mt6833uart,0x11002000 "
    "console=ttyS0,921600n8 loglevel=8 ignore_loglevel clk_ignore_unused "
    "pd_ignore_unused printk.devkmsg=on mem_sleep_default=s2idle cma=96M "
    "mt6359_regulator.a22x_lp_probe=1 mt6359_regulator.a22x_lp_stock_init=1 "
    "fbcon=logo-count:0 vt.global_cursor_default=0 a22x.recovery=1 "
    "rdinit=/init root=/dev/ram"
)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args):
    return subprocess.run([str(arg) for arg in args], check=True, text=True,
                          capture_output=True).stdout.strip()


def fdt_property(dtb, node, prop, typ="s"):
    return run("fdtget", "-t", typ, dtb, node, prop)


def validate_native_dtb(dtb):
    """Reject the simpledrm DTB that caused touch/power regressions.

    The four compatibles describe possible *hardware*, not four working
    drivers.  Only Himax JDI was tested on the physical owner's device.
    """
    dsi = "/display-ml/dsi-ml@14013000"
    panel = dsi + "/panel@0"
    touch = "/spi1@11010000/novatek@0"
    check(fdt_property(dtb, "/aliases", "dsi0") == dsi,
          "native MediaTek DSI alias missing")
    check(fdt_property(dtb, "/chosen/framebuffer@7c9b0000", "status") == "disabled",
          "LK simple-framebuffer must be disabled")
    check(fdt_property(dtb, panel, "compatible") == "jdi,hx83112f-a22x",
          "JDI native panel missing")
    check(fdt_property(dtb, touch, "panel", "x") ==
          fdt_property(dtb, panel, "phandle", "x"),
          "Himax touch must follow its powered panel")
    compatibles = set(fdt_property(dtb, touch, "compatible").split())
    check({"novatek,NVT-ts-spi", "mediatek,7807s_touch", "focaltech,ft8722",
           "himax,hx83112f", "himax,common"} <= compatibles,
          "shared SPI node lost one or more hardware variants")
    check(fdt_property(dtb, touch, "touchscreen-size-x", "u") == "1080" and
          fdt_property(dtb, touch, "touchscreen-size-y", "u") == "2408",
          "touch geometry differs from A22x panel")
    return {"panel": panel, "touch": touch, "touch_compatibles": sorted(compatibles)}


def update_ramdisk_version(blob):
    """Preserve the exact original newc archive except one same-size value."""
    uncompressed = gzip.decompress(blob)
    check(len(OLD_VERSION) == len(NEW_VERSION), "version changes cpio entry size")
    check(uncompressed.count(OLD_VERSION) == 1, "expected one 1.0.2.1 version field")
    check(uncompressed.count(NEW_VERSION) == 0, "ramdisk already claims 1.0.2.2")
    patched = uncompressed.replace(OLD_VERSION, NEW_VERSION, 1)
    check(len(patched) == len(uncompressed), "cpio archive geometry changed")
    return gzip.compress(patched, compresslevel=9, mtime=0)


def mkbootimg(parts, dtb, ramdisk, output):
    run("mkbootimg", "--kernel", parts / "kernel", "--ramdisk", ramdisk,
        "--recovery_dtbo", parts / "recovery_dtbo", "--dtb", dtb,
        "--header_version", "2", "--pagesize", "2048", "--base", "0x0",
        "--kernel_offset", "0x40080000", "--ramdisk_offset", "0x51100000",
        "--tags_offset", "0x47c80000", "--dtb_offset", "0x47c80000",
        "--board", "SRPTL28A011", "--os_version", "12.0.0",
        "--os_patch_level", "2025-01", "--cmdline", CMDLINE,
        "--output", output)
    run("avbtool", "add_hash_footer", "--image", output,
        "--partition_name", "recovery", "--partition_size", PARTITION_SIZE,
        "--algorithm", "NONE", "--salt", AVB_SALT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True,
                        help="Exact verified v1.0.2.1 SPI-guard image")
    parser.add_argument("--native-dtb", type=Path, required=True,
                        help="Compiled Linux 7.2 native-display DTB")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Nonexistent directory; never overwritten")
    args = parser.parse_args()
    base, dtb, output_dir = args.base.resolve(), args.native_dtb.resolve(), args.output_dir.resolve()
    check(not output_dir.exists(), "output directory already exists")
    check(base.is_file() and digest(base) == BASE_SHA256, "unknown 1.0.2.1 base")
    check(dtb.is_file() and digest(dtb) == NATIVE_DTB_SHA256, "unreviewed native DTB")
    fdt = validate_native_dtb(dtb)

    with tempfile.TemporaryDirectory(prefix="a22x-1022-repack-") as temp:
        temp = Path(temp)
        parts = temp / "unpacked"
        run("unpack_bootimg", "--boot_img", base, "--out", parts)
        check((parts / "dtb").read_bytes()[:4] == bytes.fromhex("d00dfeed"),
              "base input DTB has an unexpected format")
        baseline = temp / "roundtrip.img"
        mkbootimg(parts, parts / "dtb", parts / "ramdisk", baseline)
        check(digest(baseline) == BASE_SHA256,
              "baseline cannot be reproduced bit-for-bit; stop")

        new_ramdisk = temp / "ramdisk.new.gz"
        new_ramdisk.write_bytes(update_ramdisk_version((parts / "ramdisk").read_bytes()))

        output_dir.mkdir(parents=True)
        candidate = output_dir / "recovery.img"
        mkbootimg(parts, dtb, new_ramdisk, candidate)
        check(candidate.stat().st_size == PARTITION_SIZE, "wrong recovery image size")
        run("avbtool", "verify_image", "--image", candidate)
        extracted = temp / "verify"
        run("unpack_bootimg", "--boot_img", candidate, "--out", extracted)
        for name, original in (("kernel", parts / "kernel"),
                               ("recovery_dtbo", parts / "recovery_dtbo"),
                               ("ramdisk", new_ramdisk), ("dtb", dtb)):
            check(digest(extracted / name) == digest(original),
                  "packaged payload differs: " + name)
        report = {
            "version": "1.0.2.2", "source": "1.0.2.1 SPI-guard",
            "base_sha256": BASE_SHA256, "native_dtb_sha256": NATIVE_DTB_SHA256,
            "recovery_sha256": digest(candidate), "partition_bytes": PARTITION_SIZE,
            "avb": "NONE hash footer verified (not a Samsung/OEM signature)",
            "unchanged_kernel": True, "unchanged_recovery_dtbo": True,
            "initramfs_change": "build.json version field only",
            "fdt": fdt, "actual_touch": "REQUIRES_OWNER_TEST",
            "other_hardware_variants": "NOT_HARDWARE_QUALIFIED",
            "recovery_to_android": "NOT_TESTED",
        }
        (output_dir / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
