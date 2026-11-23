#!/usr/bin/env python3
"""The UI must not own cpufreq's shared sysfs minimum request.

In particular, a thermal cap below the old floor makes its effective readback
indistinguishable from a request changed by another writer. The native UI must
therefore never open this sysfs attribute, including during input or expiry.
"""
from pathlib import Path

binary = Path(__file__).resolve().parents[1] / "a22x-recovery-ui"
assert b"scaling_min_freq" not in binary.read_bytes(), "UI contains the shared cpufreq minimum path"
print('{"ok":true,"ui_shared_cpufreq_minimum_access":false}')
