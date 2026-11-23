#!/bin/bash
# libasound_module_pcm_a22x_switch.so for the phone's browser: Alpine aarch64 (musl), against the sysroot
# of tools/alpine_sysroot.py with alsa-lib-dev (as build.sh; 2026-11-22). The browser's alsa-lib is
# Alpine's, the same one the player uses.
set -euo pipefail
SR=${SYSROOT:?set SYSROOT to the sysroot of tools/alpine_sysroot.py}
OUT=${1:-libasound_module_pcm_a22x_switch.so}
cd "$(dirname "$0")"
clang --target=aarch64-linux-musl --sysroot=$SR -O2 -Wall -Wextra -Werror -std=gnu11 -fPIC -DPIC -I$SR/usr/include -c a22x_switch.c -o $OUT.o
clang --target=aarch64-linux-musl --sysroot=$SR -fuse-ld=lld -shared -nostdlib $SR/usr/lib/crti.o $OUT.o \
      -L$SR/usr/lib -L$SR/lib -lasound -lc $SR/usr/lib/crtn.o \
      -Wl,--allow-shlib-undefined -Wl,-z,relro,-z,now -Wl,-soname,libasound_module_pcm_a22x_switch.so -s -o $OUT
rm -f $OUT.o
