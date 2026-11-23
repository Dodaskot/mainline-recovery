#!/usr/bin/env python3
"""Real settings_save -> fork/exec -> settings.main/load/store, with fixture disk I/O."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

UI = Path(__file__).resolve().parents[1]
WRAPPER = r'''
import json, os, sys, time
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, os.environ["A22X_POLICY_PROJECT"])
import settings
root = Path(os.environ["A22X_POLICY_FIXTURE_ROOT"])
disk = root / "disk.json"
mode = os.environ["A22X_POLICY_FIXTURE_MODE"]
if sys.argv[1] == "set":
    with (root / "requests.jsonl").open("a") as stream:
        stream.write(json.dumps({"mode":mode,"argv":sys.argv[1:]}) + "\n")
    if mode.startswith("hold-"):
        (root / "entered").write_text("")
        deadline = time.monotonic() + 8
        while not (root / "release").exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("Fixture handoff timed out")
            time.sleep(.001)
        (root / "release").unlink()
    if mode in ("fail-before", "hold-failure"):
        raise SystemExit(2)
def write_disk(record):
    if mode in ("busy", "hold-busy"):
        return False
    disk.write_text(json.dumps(record))
    return True
def forbidden_device():
    raise AssertionError("The settings test attempted physical device I/O")
settings.fs.DeviceContext = forbidden_device
settings.write_disk = write_disk
settings.read_disk = lambda: json.loads(disk.read_text())
raise SystemExit(settings.main())
'''

def main():
    with tempfile.TemporaryDirectory(prefix="a22x-android-policy-save-") as temporary:
        root = Path(temporary)
        record = {"android_password_policy":"first_access", "brightness":20}
        for filename in ("ram.json", "disk.json"):
            (root / filename).write_text(json.dumps(record))
        helper = root / "settings-fixture.py"
        helper.write_text(WRAPPER)
        env = dict(os.environ, A22X_POLICY_PROJECT=str(UI.parent),
                   A22X_POLICY_FIXTURE_ROOT=str(root), A22X_SETTINGS_RAM=str(root / "ram.json"),
                   PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([str(UI / "android-policy-settings-test"),
                                 str(root), str(helper), sys.executable],
                                env=env, text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise AssertionError(f"C route exited {result.returncode}:\n{result.stdout}\n{result.stderr}")
        observed = json.loads(result.stdout)
        assert observed == {"ok":True, "scenarios":10, "physical_device_io":False}, observed
        requests = [json.loads(line) for line in (root / "requests.jsonl").read_text().splitlines()]
        policies = []
        for request in requests:
            args = request["argv"]
            policies.append(args[args.index("--android-password-policy") + 1]
                            if "--android-password-policy" in args else None)
        expected = [None, "startup", "first_access", None, "each_mount", "startup", None,
                    "first_access", "first_access", "startup", "each_mount",
                    "first_access", "startup", "first_access", "each_mount",
                    "first_access", "first_access", "startup", "first_access"]
        assert policies == expected, (policies, expected)
        ram = json.loads((root / "ram.json").read_text())
        disk = json.loads((root / "disk.json").read_text())
        assert ram == disk and ram["android_password_policy"] == "first_access" and ram["brightness"] == 31
        observed.update(cli_requests=len(requests), policy_arguments=policies,
                        source_sha256={str(path.relative_to(UI.parent)):
                                       hashlib.sha256(path.read_bytes()).hexdigest()
                                       for path in (UI / "recovery_ui.c", UI.parent / "settings.py")},
                        tested_routes=["settings_save", "settings_poll", "settings_flush", "settings_settle",
                                       "action", "settings.main", "settings.load", "settings.store", "settings.remember"])
        report = json.dumps(observed, indent=2) + "\n"
        if os.environ.get("A22X_POLICY_TEST_REPORT"):
            Path(os.environ["A22X_POLICY_TEST_REPORT"]).write_text(report)
        print(report, end="")

if __name__ == "__main__":
    main()
