"""First settings load must never recursively load settings from inventory."""
import contextlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import android_decrypt
import decrypt_session
from decrypt_runtime import session_support as support
import settings


class PolicyReentrancy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ram = Path(self.temp.name) / "settings.json"
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(settings, "RAM_COPY", self.ram))
        # The backend and UI commits can be tested separately. With the UI
        # integrated this selects its real helper unchanged; an older settings
        # baseline gets precisely its policy projection around the real load().
        policy = getattr(settings, "android_password_policy", None)
        if policy is None:
            def policy(record=None):
                record = settings.load() if record is None else record
                value = record.get("android_password_policy") if isinstance(record, dict) else None
                return value if type(value) is str and value in support.POLICIES else "each_mount"
        self.stack.enter_context(patch.object(settings, "android_password_policy", policy, create=True))
        self.stack.enter_context(patch.object(android_decrypt, "profile",
                                             return_value={"profile_id": "samsung-a226b-a13"}))
        self.stack.enter_context(patch.object(android_decrypt, "reusable_available", return_value=False))
        self.stack.enter_context(patch.object(android_decrypt, "write_available", return_value=False))
        for module, name in ((android_decrypt, "session_status"),
                             (decrypt_session, "detached_status"),
                             (decrypt_session, "prepared_status")):
            self.stack.enter_context(patch.object(module, name, side_effect=RuntimeError("No CE session")))
        self.stack.enter_context(patch.object(android_decrypt, "terminal_status", return_value=None))
        self.stack.enter_context(patch.object(android_decrypt, "preflight_reason", return_value=None))
        self.context = SimpleNamespace(mode="device", boot_id="00000000-0000-0000-0000-000000000001")
        self.disk_reads = 0
        self.nested_policies = []

    def inventory(self):
        volume = {"id": "userdata", "external": False, "volume_token": "a" * 64,
                  "fs_type": None, "fscrypt_feature": True}
        return android_decrypt.decorate(self.context, [volume])[0]

    def disk_read_with_inventory(self):
        self.disk_reads += 1
        # Simulate only the disk boundary, preserving the actual settings.load,
        # inventory/decorate and password_policy calls that formerly recursed.
        if self.disk_reads > 1:
            raise AssertionError("Inventory recursively reopened the settings disk")
        self.nested_policies.append(self.inventory()["android_password_policy"])
        return {"android_password_policy": "startup", "language": "uk"}

    def test_policy_enforcement_first_load_reenters_inventory_without_disk_recursion(self):
        with patch.object(settings, "read_disk", side_effect=self.disk_read_with_inventory):
            self.assertEqual(support.password_policy(), "startup")
        self.assertEqual(self.disk_reads, 1)
        self.assertEqual(self.nested_policies, ["each_mount"])
        self.assertEqual(json.loads(self.ram.read_text())["android_password_policy"], "startup")
        self.assertEqual(self.inventory()["android_password_policy"], "startup")

    def test_direct_ui_settings_load_reenters_inventory_without_a_second_load(self):
        with patch.object(settings, "read_disk", side_effect=self.disk_read_with_inventory):
            record = settings.load()
        self.assertEqual(record["android_password_policy"], "startup")
        self.assertEqual(self.disk_reads, 1)
        self.assertEqual(self.nested_policies, ["each_mount"])
        self.assertEqual(self.inventory()["android_password_policy"], "startup")

    def test_inventory_alone_never_initiates_disk_settings_discovery(self):
        with patch.object(settings, "read_disk", side_effect=AssertionError("Unexpected disk I/O")):
            self.assertEqual(self.inventory()["android_password_policy"], "each_mount")
            self.assertFalse(self.ram.exists())
            self.ram.write_text(json.dumps({"android_password_policy": "first_access"}))
            self.assertEqual(self.inventory()["android_password_policy"], "first_access")
            self.ram.write_text("damaged")
            self.assertEqual(self.inventory()["android_password_policy"], "each_mount")

    def test_reentrancy_guard_resets_after_unreadable_settings(self):
        with patch.object(settings, "read_disk", side_effect=OSError("Unavailable")):
            self.assertEqual(support.password_policy(), "each_mount")
        with patch.object(settings, "read_disk", side_effect=self.disk_read_with_inventory):
            self.assertEqual(support.password_policy(), "startup")
        self.assertEqual(self.disk_reads, 1)


if __name__ == "__main__":
    unittest.main()
