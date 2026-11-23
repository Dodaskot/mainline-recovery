#!/bin/sh
# SPDX-License-Identifier: MIT
# The host's Python tests, run as the recovery runs its helpers: as root, in a user namespace when the
# caller is not (2026-11-22: the installers give what they make to root, which a user cannot do outside
# one; 44 tests of image import failed with PermissionError so). Arguments go to pytest.
set -eu
cd "$(dirname "$0")/.."
if [ "$(id -u)" != 0 ]; then
    exec unshare -r -- python3 -m pytest -q -p no:cacheprovider tests "$@"
fi
exec python3 -m pytest -q -p no:cacheprovider tests "$@"
