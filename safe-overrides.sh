# Loaded after the reviewed vendor library. No entry point or background jobs.
DS_SAFE_ROOT=/usr/local/lib/ds-guard-safe
NDPI_DKMS_VERSION=1.7.63880be7697-dsg2
NDPI_ARTIFACT_DKMS_VERSION=disabled
NDPI_HELPER_VARS="$NDPI_HELPER_VARS DS_SAFE_ROOT"
NDPI_HELPER_FUNCS="$NDPI_HELPER_FUNCS safe_patch_source"
safe_patch_source(){ python3 "$DS_SAFE_ROOT/patch_sources.py" "$1"; }
ndpi_artifact_install(){ return 1; } # Original vendor binaries lack the reviewed fixes.
ndpi_plugin_fits(){
  local xt t rc=1 chain="DSG_PROBE_${BASHPID}"
  xt="$(ndpi_plugin_path)" && [ -f "$1" ] && t="$(mktemp -d)" || return 1
  if cp "$1" "$t/libxt_ndpi.so" && iptables -w 5 -N "$chain"; then
    XTABLES_LIBDIR="$t:${xt%/*}" iptables -w 5 -A "$chain" -m ndpi --proto bittorrent -j RETURN >>"$LOG" 2>&1 && rc=0
    iptables -w 5 -F "$chain" && iptables -w 5 -X "$chain" || rc=1
  fi
  rm -f "$t/libxt_ndpi.so"; rmdir "$t"
  return "$rc"
}
ensure_repos(){ :; } # Never rewrite the server's repository configuration.
install_header_meta(){ :; } # Never pull a new kernel indirectly.
apt_install(){
 local rc=0
 python3 "$DS_SAFE_ROOT/ubuntu_apt.py" --transaction "${DS_TXN:-}" "$@" >>"$LOG" 2>&1 || rc=$?
 if [ "$rc" = 124 ]; then
  [ -n "${DS_TXN:-}" ] && : >"$DS_TXN/package-timeout"
 fi
 return "$rc"
}
suricata_install(){
  python3 "$DS_TXN/transaction.py" suricata-arm "$DS_TXN" || return 1
  apt_install suricata || return 1
  python3 "$DS_SAFE_ROOT/transaction.py" capture-package-default "$DS_TXN"
}
ndpi_dkms_tree(){
  local src="/usr/src/ndpi-$NDPI_DKMS_VERSION"
  # A versioned tree is immutable once registered. No removal of older versions.
  [ ! -e "$src" ] || { echo "Source version already exists: $src"; return 1; }
  cp -a "$1" "$src" || return 1
  cp "$DS_SAFE_ROOT/dkms-build.sh" "$src/ds-dkms-build.sh" || return 1
  chmod 0755 "$src/ds-dkms-build.sh"
  cat > "$src/dkms.conf" <<DK
PACKAGE_NAME="ndpi"
PACKAGE_VERSION="$NDPI_DKMS_VERSION"
BUILT_MODULE_NAME[0]="xt_ndpi"
BUILT_MODULE_LOCATION[0]="ndpi-netfilter/src"
DEST_MODULE_LOCATION[0]="/updates/dkms"
MAKE[0]="bash ds-dkms-build.sh \${kernelver}"
CLEAN="make -C ndpi-netfilter/src KERNEL_DIR=/lib/modules/\${kernelver}/build clean"
DK
}
build_ndpi(){
  local src="/usr/src/ndpi-$NDPI_DKMS_VERSION" build="$DS_TXN/source" ko so
  ndpi_lock 0 || { echo 'Another module build is running'; return 1; }
  if [ -d "$DS_SAFE_ROOT/assets/$KREL" ]; then
    python3 "$DS_SAFE_ROOT/install_prebuilt.py" >>"$LOG" 2>&1 || return 1
    ndpi_conf && write_ndpi_helper || return 1
    ndpi_unlock; return 0
  fi
  if ! [ -f "$src/dkms.conf" ]; then
    apt_install build-essential git autoconf automake libtool pkg-config libpcap-dev libgcrypt20-dev flex bison libxtables-dev dkms || return 1
    [ -d "/lib/modules/$KREL/build" ] || apt_install_headers "linux-headers-$KREL" || return 1
    [ -d "/lib/modules/$KREL/build" ] || return 1
    if grep -qx 'CONFIG_CC_IS_GCC=y' "/boot/config-$KREL"; then
      local gv major
      gv=$(sed -n 's/^CONFIG_GCC_VERSION=//p' "/boot/config-$KREL");major=$((gv / 10000))
      command -v "gcc-$major" >/dev/null || apt_install "gcc-$major" || return 1
    fi
    fetch_pinned_ndpi "$build" >>"$LOG" 2>&1 || return 1
    ( cd "$build" && ./autogen.sh && ./configure && make -j2 && make -C ndpi-netfilter/ipt ) >>"$LOG" 2>&1 || return 1
    ndpi_dkms_tree "$build" || return 1
    dkms add -m ndpi -v "$NDPI_DKMS_VERSION" >>"$LOG" 2>&1 || return 1
  fi
  # Immutable source, bounded compilation; no modprobe before this succeeds.
  timeout 25m dkms build -m ndpi -v "$NDPI_DKMS_VERSION" -k "$KREL" >>"$LOG" 2>&1 || return 1
  timeout 5m dkms install -m ndpi -v "$NDPI_DKMS_VERSION" -k "$KREL" --force >>"$LOG" 2>&1 || return 1
  so="$src/ndpi-netfilter/ipt/libxt_ndpi.so"
  [ -s "$so" ] || return 1
  local xtdir; xtdir=$(pkg-config --variable=xtlibdir xtables)
  [ -d "$xtdir" ] || return 1
  install -m 0644 "$so" "$xtdir/libxt_ndpi.so" || return 1
  ndpi_conf || return 1
  write_ndpi_helper || return 1
  ndpi_unlock
}
# Kernel hooks may prepare a supported kernel; they cannot silently use an
# unreviewed destructor on a new major/minor release or replace the host kernel.
ndpi_kprep(){
  local k="${1:-}"
  case "$k" in 6.8.0-87-generic|6.8.0-147-generic|7.0.12-x64v2-dsg1-xanmod1|7.2.9-x64v3-dsg1-xanmod1) ;; *) logger -t ds-guard 'Kernel requires compatibility review'; return 1;; esac
  grep -qs '^CONFIG_LIVEPATCH=y$' "/boot/config-$k" || return 1
  [ -d "/lib/modules/$k/build" ] || return 1
  ndpi_lock 0 || return 1
  timeout 25m dkms build -m ndpi -v "$NDPI_DKMS_VERSION" -k "$k" && timeout 5m dkms install -m ndpi -v "$NDPI_DKMS_VERSION" -k "$k" --force
  local rc=$?; ndpi_unlock; return "$rc"
}
. "$DS_SAFE_ROOT/suricata-setup.sh"
