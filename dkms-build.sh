#!/usr/bin/env bash
set -euo pipefail
kernelver="$1"
[[ "$kernelver" =~ ^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$ ]] || exit 78
case "$kernelver" in 6.8.0-87-generic|6.8.0-147-generic|7.0.12-x64v2-dsg1-xanmod1|7.2.9-x64v3-dsg1-xanmod1) ;; *) echo 'Kernel compatibility not admitted'; exit 78;; esac
grep -qx 'CONFIG_LIVEPATCH=y' "/boot/config-$kernelver" || exit 78
extra=()
if grep -qx 'CONFIG_CC_IS_CLANG=y' "/boot/config-$kernelver"; then
  cv=$(sed -n 's/^CONFIG_CLANG_VERSION=//p' "/boot/config-$kernelver")
  major=$((cv / 10000))
  command -v "clang-$major" >/dev/null || { echo "Install official LLVM $major first"; exit 78; }
  extra+=("LLVM=-$major")
else
  gv=$(sed -n 's/^CONFIG_GCC_VERSION=//p' "/boot/config-$kernelver")
  major=$((gv / 10000))
  command -v "gcc-$major" >/dev/null || { echo "Matching GCC $major is required"; exit 78; }
  extra+=("CC=gcc-$major" "HOSTCC=gcc-$major")
fi
exec make -j2 -C ndpi-netfilter/src KERNEL_DIR="/lib/modules/$kernelver/build" modules EXTRA_CFLAGS='-std=gnu99 -Wno-error=implicit-function-declaration' "${extra[@]}"
