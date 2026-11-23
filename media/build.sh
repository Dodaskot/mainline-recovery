#!/bin/bash
# a22x-media for the phone: Alpine aarch64 (musl), against the sysroot tools/alpine_sysroot.py made of
# musl-dev ffmpeg-dev alsa-lib-dev linux-headers (2026-11-22).
set -euo pipefail
SR=${SYSROOT:?set SYSROOT to the sysroot of tools/alpine_sysroot.py}
OUT=${1:-a22x-media}
cd "$(dirname "$0")"
clang --target=aarch64-linux-musl --sysroot=$SR -O2 -Wall -Wextra -Werror -std=gnu11 -fPIE -I$SR/usr/include -c a22x_media.c -o $OUT.o
clang --target=aarch64-linux-musl --sysroot=$SR -fuse-ld=lld -pie -nostdlib $SR/usr/lib/Scrt1.o $SR/usr/lib/crti.o $OUT.o \
      -L$SR/usr/lib -L$SR/lib -lavformat -lavcodec -lswresample -lswscale -lavutil -lasound -lc $SR/usr/lib/crtn.o \
      -Wl,-dynamic-linker,/lib/ld-musl-aarch64.so.1 -Wl,--allow-shlib-undefined -Wl,-z,relro,-z,now -s -o $OUT
rm -f $OUT.o
