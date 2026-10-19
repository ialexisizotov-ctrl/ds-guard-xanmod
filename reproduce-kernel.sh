#!/bin/bash
# Run on a separate Ubuntu 24.04 build machine, never on production.
set -euo pipefail
release=${1:?Usage: bash reproduce-kernel.sh 7.0.12|7.2.9 /new/build/path}
destination=${2:?A new empty absolute build path is required}
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
case "$release" in
  7.0.12) commit=945bad56c1ffa8458975c557b855a6d8efef0319; cpu=x64v2;;
  7.2.9) commit=bca689d38274338b44a54e3bb198547c8eab8fc0; cpu=x64v3;;
  *) echo 'Unreviewed source release'; exit 78;;
esac
[[ "$destination" = /* && ! -e "$destination" ]] || { echo 'Use a new absolute directory'; exit 1; }
for tool in git clang-21 ld.lld-21 make bison flex pahole dpkg-deb; do command -v "$tool" >/dev/null; done
mkdir -p -- "$destination"
git clone --depth 1 --branch "$release-xanmod1" https://gitlab.com/xanmod/linux.git "$destination/linux"
cd -- "$destination/linux"
test "$(git rev-parse HEAD)" = "$commit"
mkdir ../out
cp "$here/config-$release-$cpu-xanmod1" ../out/.config
scripts/config --file ../out/.config --enable LIVEPATCH --set-str LOCALVERSION "-$cpu-dsg1"
make O=../out LLVM=-21 olddefconfig
grep -qx 'CONFIG_LIVEPATCH=y' ../out/.config
scripts/diffconfig "$here/config-$release-$cpu-xanmod1" ../out/.config > ../config-diff.txt
nice -n 10 make -j"${JOBS:-2}" O=../out LLVM=-21 KDEB_PKGVERSION="$release-dsg1" KBUILD_BUILD_USER=dsguard KBUILD_BUILD_HOST=builder bindeb-pkg
printf 'Build output: %s\n' "$destination"
