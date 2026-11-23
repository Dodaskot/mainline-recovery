"""Cross-layer packaging admission regression; no device I/O."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import android_decrypt
from decrypt_runtime.common import validate_config, SessionError, STATE_DIR
from tests.test_decrypt_session import CONFIG, BOOT

class ProfilePinTests(unittest.TestCase):
    def test_packaged_manifest_is_admitted_by_frontend_and_supervisor(self):
        profile = json.loads((Path(__file__).resolve().parents[1] /
            "profiles/android-decrypt/samsung-a226b-a13.json").read_text())
        with patch.object(android_decrypt, "regular_json", return_value=profile), \
             patch.object(android_decrypt.Path, "read_text", return_value="Linux #152 qualified"):
            self.assertEqual(android_decrypt.profile(), profile)
        self.assertEqual(profile["kernel_build"], 152)
        for other in ("Linux #146 qualified", "Linux #1520 qualified", "Linux 152 qualified"):
            with patch.object(android_decrypt, "regular_json", return_value=profile), \
                 patch.object(android_decrypt.Path, "read_text", return_value=other):
                with self.assertRaises(ValueError):
                    android_decrypt.profile()
        config = copy.deepcopy(CONFIG)
        config["state_dir"] = STATE_DIR
        config["root_manifest_sha256"] = profile["root_manifest_sha256"]
        validate_config(config, actual_boot=BOOT)
        for rejected in ("0" * 64,
                "60caf8e0574855048c10cb25f845c3377886c3d5cbbec1aeba383fdf5f16aea0"):
            config["root_manifest_sha256"] = rejected
            with self.assertRaises(SessionError):
                validate_config(config, actual_boot=BOOT)
        self.assertEqual(profile["credential_types"], ["password", "pattern"])
        self.assertTrue(profile["credential_discovery"])

if __name__ == "__main__":
    unittest.main()
