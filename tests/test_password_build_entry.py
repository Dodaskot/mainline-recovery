"""Exercise the actual shell entry without running a heavy image build."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class PasswordBuildEntryTests(unittest.TestCase):
    def invoke(self, extra):
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "python3"
            stub.write_text("#!/usr/bin/python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
            stub.chmod(0o755)
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith("A22X_") and k not in ("PUBLIC", "VERSION")}
            env.update(PATH=tmp + ":" + env["PATH"], A22X_RECOVERY_WORK=str(ROOT.parent))
            env.update(extra)
            return subprocess.run(["bash", str(ROOT/"tools/build-image.sh"), "999-check"],
                                  env=env, capture_output=True, text=True)

    def test_routes_to_qualified_builder_with_exact_arguments(self):
        p = self.invoke({"A22X_ANDROID_DECRYPT": "1",
                         "A22X_ANDROID_DECRYPT_BASE_IMAGE": "/fixture/base image.img",
                         "A22X_ANDROID_DECRYPT_RUNTIME_ARCHIVE": "/fixture/runtime archive.tar",
                         "A22X_ANDROID_DECRYPT_WIFI_MODULES": "/fixture/wifi modules.tar.xz"})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), [
            "-B", str(ROOT/"tools/build_decrypt_image.py"),
            "--base", "/fixture/base image.img",
            "--runtime", "/fixture/runtime archive.tar",
            "--wifi-modules", "/fixture/wifi modules.tar.xz",
            "--output", str(ROOT.parent/"build-password-999-check"),
            "--version", "1.1.999-check"])

    def test_missing_inputs_fail_before_build_or_removal(self):
        p = self.invoke({"A22X_ANDROID_DECRYPT": "1"})
        self.assertEqual(p.returncode, 2)
        self.assertIn("requires", p.stderr)
        self.assertEqual(p.stdout, "")

    def test_missing_matching_wifi_fails_before_builder(self):
        p = self.invoke({"A22X_ANDROID_DECRYPT": "1",
                         "A22X_ANDROID_DECRYPT_BASE_IMAGE": "/fixture/base image.img",
                         "A22X_ANDROID_DECRYPT_RUNTIME_ARCHIVE": "/fixture/runtime archive.tar"})
        self.assertEqual(p.returncode, 2)
        self.assertIn("A22X_ANDROID_DECRYPT_WIFI_MODULES", p.stderr)
        self.assertEqual(p.stdout, "")

    def test_public_personal_profile_is_refused(self):
        p = self.invoke({"A22X_ANDROID_DECRYPT": "1", "PUBLIC": "1"})
        self.assertEqual(p.returncode, 2)
        self.assertIn("PUBLIC=1 is not qualified", p.stderr)

    def test_unknown_mode_is_refused(self):
        p = self.invoke({"A22X_ANDROID_DECRYPT": "2"})
        self.assertEqual(p.returncode, 2)
        self.assertIn("must be 1", p.stderr)

if __name__ == "__main__":
    unittest.main()
