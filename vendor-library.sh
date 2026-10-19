#!/bin/bash
# DoubleServers VPS Guard for Ubuntu/Debian: nDPI, Suricata and exact domains.
# Config: DS_TORRENT=1 DS_PACKETSDK=1 DS_DOMAINS="" DS_WAN=auto.
# Usage: ds-guard.sh [--uninstall|--status|--dry-run]
set -u
export DEBIAN_FRONTEND=noninteractive
# needrestart restarts services after apt; it must not restart what runs us.
export NEEDRESTART_SUSPEND=1
VERSION="1.7.11"
LOG=/var/log/ds-guard-install.log
NDPI_REPO="https://github.com/vel21ripn/nDPI.git"
NDPI_COMMIT="63880be7697149ce954c91346bbd7b8cb8ea34d0"
NDPI_SOURCE_ARCHIVE_SHA256="211021fab72aadb660085fba9491ac38c7f94a21194b67b0c5c115ac467e22ae"
# A fixed DKMS version made reruns reuse an old build for the running kernel.
NDPI_DKMS_VERSION="1.7.${NDPI_COMMIT:0:11}"
# Kernels older than 5.18 build with gnu89 and reject implicit declarations;
# these are the same compatibility flags as the 2.x installer.
NDPI_KCFLAGS="-std=gnu99 -Wno-error=implicit-function-declaration"
STATE_DIR=/etc/ds-guard
SBIN=/usr/local/sbin
CONNTRACK_SYSCTL=/etc/sysctl.d/99-ds-guard-conntrack.conf

PKG_FAMILY=apt
NDPI_ARTIFACT_DKMS_VERSION="2.0.63880be7697"
NDPI_SIGNING_POLICY_SHA256="66d432191712b26133b7efec1215bd0131f356c2ecf12a94311283f1917d4e99"
NDPI_ARTIFACT_PUBKEY_SHA256="21e4f40d51c8b4c422dac0c556124f9ee285b250b23600f0816b0a3c50f197b8"
DS_NDPI_ARTIFACT_PUBLIC_KEY_B64="MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyEDJMZ92vxrTCuAq7FM+5duhRZ8Y3thHFFge2pTAY7mAOLaYYNQkXP+UvkTFVbJlzV4yaWdUwhrOry+T2+L1HVbECnkM0FkW749UKMTUJZvw1XSwURjGGtqbq5Y8cu2k7oPP5PiElvESwRkWOYBTnEzKub7rV3ot9N3/g5aS+JmyWMRwmUuILCR8DnCSFHPS6xTos2bhbO7+IDJ4k76kru83qnchycQlzD2SE0RRes0j4P0htQcic24fKzjT4exiQlgksTleQAMNoRp87kv9ANq2zkICCqlLjaOd+rIsRcYAYuX8+Aw3eO50W9EgFBuohSbgK/0M0a2qLaw+59jleFhCsbAd/h2HER2teDh6y/3YfcuAnYe0VBwiX6Fh0AopN5RJiyC2C1nluyqGscCh+5DefR9rIZ+mwMLgxKYeCg8z8FU/udFp9F4y29ipdzbOUoMkJRxvW/tRn8FF+tbGA3OgCoP/l9qh42PJ8kVNZs9xXv3iAUShFMUje60XZBamz1oYQoMvWwrTIAoMc4Oggx4cQxKD3DRKZMMQledvOIOF/UViYsBFUVbozcMQqaIkEaqRqGwcoFLWim6UgN5TH54L7EWoXoxoedfgJ4plwmLwJPJRo/XchHltlMl4ketdgkhJmSvG5fi9MoUrkfjGxea+dzETU67ZWH5rgkW/XLUCAwEAAQ=="
DS_NDPI_ARTIFACT_RELEASE=v1
DS_NDPI_REVOKED_MANIFESTS=""
DS_NDPI_ARTIFACT_BASE_URL="${DS_GUARD_ARTIFACT_BASE:-https://guard.doubleservers.network/ds-guard-artifacts}"
NDPI_ARTIFACT_STATE="$STATE_DIR/ds17-artifact"
NDPI_DKMS_FAILED="$STATE_DIR/ds17-dkms-failed"
NDPI_STAGE_DIR=/opt/ds-guard-ndpi-src
NDPI_GIT_TIMEOUT=600
NDPI_STAGE_BUILD_TIMEOUT=1800
NDPI_HELPER="$SBIN/ds-guard-ndpi-lib.sh"

DS_TORRENT="${DS_TORRENT:-1}"
DS_PACKETSDK="${DS_PACKETSDK:-1}"
DS_DOMAINS="${DS_DOMAINS:-}"
DS_WAN="${DS_WAN:-auto}"
DOMAIN_REQUESTED=0; { [ "$DS_TORRENT" = 1 ] || [ "$DS_PACKETSDK" = 1 ] || [ -n "$DS_DOMAINS" ]; } && DOMAIN_REQUESTED=1

torrent_site_domains(){ cat <<'DOMAINS'
1337x.to
1337x.tw
1tamilmv.ing
1vegamovies.cfd
anime-sama.to
animepahe.com
animepahe.org
animepahe.pw
animepahe.ru
animeunity.so
aniwaves.ru
bench.utorrent.com
bitru.org
burningseries.ac
cdnmovies-stream.online
cuevana3.si
cuevana3i.bio
ext.to
eztvx.to
fanserial.me
filmixapp.cyou
fitgirl-repacks.site
hd-repka.pro
hd-rezka.one
hd-rezka.pro
hd-rezka.st
hd-rezka.su
hd-rezka.tv
hdrezka-film.tv
hdrezka-home.tv
hdrezka-kino.tv
hdrezka-play.com
hdrezka.ag
hdrezka.ax
hdrezka.blog
hdrezka.cab
hdrezka.cam
hdrezka.center
hdrezka.chat
hdrezka.city
hdrezka.club
hdrezka.co
hdrezka.co.uk
hdrezka.cyou
hdrezka.day
hdrezka.fans
hdrezka.film
hdrezka.fm
hdrezka.fyi
hdrezka.in
hdrezka.inc
hdrezka.info
hdrezka.it
hdrezka.kim
hdrezka.mn
hdrezka.mx
hdrezka.news
hdrezka.plus
hdrezka.rest
hdrezka.run
hdrezka.sb
hdrezka.show
hdrezka.st
hdrezka.tips
hdrezka.video
hdrezka.win
hdrezka.zone
hdrzk.org
hello-rezka.tv
hydrahd.ru
hydrahd.ws
kinobase.org
kinogo.ae
kinogo.direct
kinogo.ec
kinogo.holiday
kinogo.luxury
kinogo.rehab
kinogo.solar
kinogo.wales
kinozal.guru
kinozal.me
kinozal.tv
kisskh.co
kisskh.do
kisskh.is
knaben.org
limetorrents.lol
lordfilm5.pro
lordfilm64.com
m1.rezka2.homes
magnetdl.co
magnetdl.org
maxitorrent.net
megapeer.vip
netmirror.gg
netmirror.global
netmirror.plus
netmirrors.org
nnmclub.to
nyaa.si
omnirezka.tv
pirateproxy.lat
pornolab.net
rarbgmirror.com
rargb.to
rezka-club.tv
rezka-films.biz
rezka-kz.me
rezka-ua.co
rezka-ua.in
rezka-ua.live
rezka-ua.org
rezka-ua.pro
rezka-ua.to
rezka-ua.tv
rezka.ac
rezka.ag
rezka.ai
rezka.ax
rezka.biz
rezka.black
rezka.city
rezka.fi
rezka.it
rezka.llc
rezka.loan
rezka.mobi
rezka.mov
rezka.plus
rezka.pub
rezka.top
rezkaua.pro
rivestream.ru
rustorka.com
rutor.info
rutor.is
rutracker.org
serienstream.to
skidrowreloaded.com
soap2day.day
standby-rezka.tv
streamalloha.live
streamingcommunityz.company
streamingcommunityz.tech
streamingunity.dog
tapochek.net
the-hdrezka.net
thealloha.club
thepiratebay.org
toloka.to
torlock.com
torlock2.com
torrends.info
torrends.to
torrent.by
torrent9.gg
torrent9.so
torrent9.to
torrentfunk.com
torrentfunk2.com
torrentstream.org
update.utorrent.com
vegamovies.futbol
vegamovies.gallery
vokino.pro
www10.rezka.work
www8.rezka.work
www9.rezka.work
yggtorrent.top
yourbittorrent.com
yts-official.org
yts-official.to
yts.bz
yts.lt
zona.im
zona.plus
zona.pub
zona.ru
DOMAINS
}

packetsdk_ioc_domains(){ cat <<'DOMAINS'
00857cca77b615c369f48ead5f8eb7f3.com
0aa0cf0637d66c0d.com
31d58c226fc5a0aa976e13ca9ecebcc8.com
3k7m1n9p4q2r6s8t0v5w2x4y6z8u9.com
442fe7151fb1e9b5.com
6b86b273ff34fce1.online
7x2k9n4p1q0r5s8t3v6w0y2z4u7b9.com
8b21a945159f23b740c836eb50953818.com
8f00b204e9800998.com
a7b37115ce3cc2eb.com
a8d3b9e1f5c7024d6e0b7a2c9f1d83e5.com
aa86a52a98162b7d.com
af4760df2c08896a9638e26e7dd20aae.com
asdk2.com
b5e9a2d7f4c8e3b1a0d6f2e9c5b8a7d.com
bdrv7wlbszfotkqf.uk
castarsdk.com
cfe47df26c8eaf0a7c136b50c703e173.com
e4f8c1b9a2d7e3f6c0b5a8d9e2f1c4d.com
earnsdk.io
hexsdk.com
holadns.com
martianinc.co
okamiboss.com
v46wd6uramzkmeeo.in
willmam.com
DOMAINS
}

normalize_domain(){
  local d label escaped framed; d="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"; d="${d%.}"
  # xt_string accepts at most 128 decoded bytes; keep room for DNS label bytes
  # and the anchored host-regex framing.
  [ -n "$d" ] && [ "${#d}" -le 79 ] && [[ "$d" == *.* ]] \
    && [[ "$d" =~ ^[a-z0-9.-]+$ ]] && [[ "$d" != .* ]] && [[ "$d" != *. ]] && [[ "$d" != *..* ]] \
    || return 1
  case "$d" in *[!0-9.]*);; *) return 1;; esac
  local IFS=. labels=(); read -r -a labels <<<"$d"
  for label in "${labels[@]}"; do
    [ "${#label}" -ge 1 ] && [ "${#label}" -le 63 ] \
      && [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
  done
  escaped="${d//./\\.}"; framed="/(^|\\.)(${escaped})$/"
  [ "${#framed}" -lt 127 ] || return 1
  printf '%s\n' "$d"
}

c_g="\033[1;32m"; c_y="\033[1;33m"; c_r="\033[1;31m"; c_c="\033[1;34m"; c_0="\033[0m"
# The detailed journal goes to $LOG only; the terminal gets step headers and
# [SUCCESS]/[SKIPPED]/[FAILED]. The braces keep bash's own "Permission denied"
# for an unwritable $LOG (non-root run) off the screen.
_flog(){ { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$1" >> "$LOG"; } 2>/dev/null || true; }
log(){ _flog "$*"; }
ok(){  _flog "[ok] $*"; }
LAST_WARN=""; VERIFY_S=0; VERIFY_T=0
warn(){ _flog "[warn] $*"; LAST_WARN="$*"; }
err(){ _flog "[fail] $*"; printf '%b[FAILED]%b %s\n' "$c_r" "$c_0" "$*"; }
die(){ err "$*"; _flog "aborting."; exit 1; }
step(){ _flog "=== $* ==="; printf '%b%s%b\n' "$c_c" "$*" "$c_0"; }
success(){ _flog "[success]"; printf '%b[SUCCESS]%b\n' "$c_g" "$c_0"; }
skip(){ _flog "[skip] $*"; printf '%b[SKIPPED]%b %s\n' "$c_y" "$c_0" "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
retry(){ local n=$1; shift; local i=1; until "$@"; do [ "$i" -ge "$n" ] && return 1; warn "retry $i/$n"; sleep $((i*3)); i=$((i+1)); done; }
APT_NET_OPTS="-o Acquire::ForceIPv4=true -o Acquire::Retries=3 -o Acquire::http::Timeout=25 -o Acquire::https::Timeout=25"
apt_install(){ retry 3 apt-get $APT_NET_OPTS -o DPkg::Lock::Timeout=300 -y -q install "$@" >>"$LOG" 2>&1; }
# New headers make dpkg's dkms hook build every DKMS module of the server for
# that kernel (a VPN module, say). Ubuntu's hook ignores their build errors only
# with this variable; without it one broken module leaves the headers package
# half-configured and every later apt run failing.
apt_install_headers(){ ( export RELEASE_UPGRADE_IN_PROGRESS=1; apt_install "$@" ); }
ensure_repos(){
  # nDPI/Suricata build deps (dkms, libpcap-dev, libxtables-dev, suricata, flex, bison...)
  # live in the 'universe' component. Minimal/cloud images sometimes ship without it,
  # which makes those packages "have no installation candidate". Enable it before deps.
  # Компонент universe есть только у Ubuntu. До 1.7.3 скрипт дописывал его и на
  # Debian, после чего каждый apt update ругается «doesn't have the component
  # 'universe'» — снимаем свою же дописку и больше её не делаем.
  if [ "$ID" != ubuntu ]; then
    local f
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
      [ -f "$f" ] && grep -qE '^[[:space:]]*deb .* universe[[:space:]]*$' "$f" || continue
      sed -i -E '/^[[:space:]]*deb .* main/ s/[[:space:]]+universe[[:space:]]*$//' "$f"
      log "removed the non-Debian 'universe' component from $f"
    done
    for f in /etc/apt/sources.list.d/*.sources; do
      [ -f "$f" ] && grep -qE '^Components:.* universe[[:space:]]*$' "$f" || continue
      sed -i -E '/^Components:/ s/[[:space:]]+universe[[:space:]]*$//' "$f"
      log "removed the non-Debian 'universe' component from $f"
    done
    return 0
  fi
  if grep -rhqs -E 'universe' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
    return 0
  fi
  log "universe repo not enabled: adding it (needed for build deps + suricata)"
  local did=0 f
  # deb822 format (Ubuntu 24.04 /etc/apt/sources.list.d/ubuntu.sources)
  for f in /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] || continue
    if grep -q '^Components:' "$f" && ! grep -q '^Components:.*universe' "$f"; then
      sed -i -E '/^Components:/ s/$/ universe/' "$f"; did=1
    fi
  done
  # legacy one-line format (deb ... noble main ...)
  if [ -f /etc/apt/sources.list ] && grep -qE '^[[:space:]]*deb .* main' /etc/apt/sources.list && ! grep -qE '^[[:space:]]*deb .* universe' /etc/apt/sources.list; then
    sed -i -E '/^[[:space:]]*deb .* main/ { /universe/! s/[[:space:]]*$/ universe/ }' /etc/apt/sources.list; did=1
  fi
  # last resort
  if [ "$did" = 0 ] && have add-apt-repository; then
    add-apt-repository -y universe >>"$LOG" 2>&1 && did=1
  fi
  [ "$did" = 1 ] && ok "universe enabled" || warn "could not enable universe automatically"
}

# ============================ PREFLIGHT =====================================
# ds-guard 2.x (installed by DoubleServers on new Hetzner servers) uses the same
# paths and unit names and ties ssh/docker/VPN units to ds-guard.service. Running
# 1.x over it would replace its units, and --uninstall would stop SSH with them.
# Not the bare /usr/local/lib/ds-guard/ds-guard.sh: 2.x copies it first and its
# --uninstall leaves it behind, so it proves neither install nor protection.
guard2_installed(){
  [ -e /etc/systemd/system/ssh.service.d/zz-ds-guard.conf ] \
    || [ -e /etc/systemd/system/suricata.service.d/zz-ds-guard-nfqueue.conf ] \
    || grep -qs -- '--apply-gate' /etc/systemd/system/ds-guard-apply.service
}
refuse_on_guard2(){
  guard2_installed || return 0
  local rc=0
  if systemctl is-active --quiet ds-guard.service 2>/dev/null; then
    printf '%b[SUCCESS]%b This server is already protected by DoubleServers ds-guard 2.x — nothing to do.\n' "$c_g" "$c_0"
  else
    printf '%b[NOTICE]%b DoubleServers ds-guard 2.x is installed here, but ds-guard.service is not active (see: systemctl status ds-guard). This script will not replace it.\n' "$c_y" "$c_0"
    rc=1
  fi
  case "${1:-}" in
    --status) [ -x /usr/local/lib/ds-guard/ds-guard.sh ] && exec /usr/local/lib/ds-guard/ds-guard.sh --status;;
    --uninstall) echo "ds-guard 2.x is removed by its own installer, not by this script.";;
  esac
  exit "$rc"
}

preflight(){
  [ "$(id -u)" = 0 ] || die "must run as root"
  mkdir -p "$STATE_DIR" "$SBIN"
  # Append: the journal of an earlier run is what support reads after a failure.
  { : >> "$LOG"; } 2>/dev/null || LOG=/tmp/ds-guard-install.log
  log "=== ds-guard v$VERSION  $(date -u) ==="
  [ -r /etc/os-release ] || die "no /etc/os-release"
  # Только ID и VERSION_ID, в подоболочке: сам os-release задаёт VERSION и затёр бы
  # версию ds-guard в итоговой строке (клиенты присылают её снимком).
  ID=$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-}")
  VERSION_ID=$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID:-}")
  case "${ID:-}" in
    ubuntu|debian) ok "OS: ${ID} ${VERSION_ID:-?}";;
    *) die "unsupported OS '${ID:-?}' (Ubuntu/Debian only)";;
  esac
  KREL="$(uname -r)"
  VIRT="$(systemd-detect-virt 2>/dev/null || echo unknown)"
  case "$VIRT" in
    openvz|lxc|lxc-libvirt|docker|podman|wsl) MODULES_OK=0; warn "virt=$VIRT: container: kernel modules not loadable (nDPI/NFQUEUE limited)";;
    *) MODULES_OK=1; ok "virt=$VIRT: own kernel";;
  esac
  if [ "$DS_WAN" = auto ]; then WAN="$(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')"; else WAN="$DS_WAN"; fi
  { [ -n "${WAN:-}" ] && ip link show "$WAN" >/dev/null 2>&1; } || die "cannot determine WAN interface (set DS_WAN=)"
  ok "WAN interface: $WAN"
  have iptables || apt_install iptables
  IPT="iptables -w"; $IPT -S >/dev/null 2>&1 || die "iptables not functional"
  [ -d "/lib/modules/$KREL/build" ] && HEADERS_OK=1 || HEADERS_OK=0
}

base_deps(){
  step "Adding repositories"
  ensure_repos
  success
  step "Updating packages"
  if ! retry 3 apt-get $APT_NET_OPTS -o DPkg::Lock::Timeout=300 -y -q update >>"$LOG" 2>&1; then
    warn "apt update failed: falling back to archive.ubuntu.com"
    sed -i -E 's#https?://mirror\.hetzner\.com/ubuntu/packages#http://archive.ubuntu.com/ubuntu#g; s#https?://mirror\.hetzner\.com/ubuntu/security#http://security.ubuntu.com/ubuntu#g; s#https?://mirror\.hetzner\.com/ubuntu#http://archive.ubuntu.com/ubuntu#g' /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true
    retry 3 apt-get $APT_NET_OPTS -o DPkg::Lock::Timeout=300 -y -q update >>"$LOG" 2>&1 || warn "apt update issues (after fallback)"
  fi
  success
  step "Installing packages"
  apt_install ca-certificates curl iptables openssl >>"$LOG" 2>&1 || warn "some base deps failed"
  STRING_OK=0; $IPT -m string -h >/dev/null 2>&1 && STRING_OK=1
  NFQ_OK=0; modprobe nfnetlink_queue 2>/dev/null; $IPT -m conntrack -h >/dev/null 2>&1 && NFQ_OK=1
  ok "caps: string=$STRING_OK nfqueue=$NFQ_OK headers=$HEADERS_OK modules=$MODULES_OK"
  success
}

# ============================ L1: nDPI ======================================
# The signed-bundle builder sources this file up to the unique inert marker
# `# DS_GUARD_LIBRARY_END_V1` and calls verify_ndpi_artifact_bundle itself. Keep
# everything above that entry point definition-only: this checks that a bundle
# will be accepted by this exact installer before it is published.
ndpi_safe_atom(){ [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$ ]]; }

ndpi_manifest_value(){
  local file="$1" key="$2" count value
  count="$(grep -c "^${key}=" "$file" 2>/dev/null || true)"
  [ "$count" = 1 ] || return 1
  value="$(sed -n "s/^${key}=//p" "$file")"
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}

ndpi_architecture(){
  [ "$PKG_FAMILY" = apt ] || return 1
  local architecture
  architecture="$(dpkg --print-architecture 2>/dev/null || true)"
  case "$architecture" in amd64|arm64) printf '%s' "$architecture";; *) return 1;; esac
}

ndpi_iptables_version(){
  local version
  version="$(iptables --version 2>/dev/null | sed -nE 's/^iptables v([^ ]+).*/\1/p')"
  ndpi_safe_atom "$version" || return 1
  printf '%s' "$version"
}

ndpi_plugin_path(){
  local candidate resolved
  for candidate in /usr/lib/*-linux-gnu/xtables/libxt_tcp.so \
      /usr/lib/xtables/libxt_tcp.so /lib/*-linux-gnu/xtables/libxt_tcp.so; do
    [ -f "$candidate" ] || continue
    resolved="$(readlink -f "$(dirname "$candidate")" 2>/dev/null || true)"
    case "$resolved" in /usr/lib/*/xtables|/usr/lib/xtables)
      printf '%s/libxt_ndpi.so' "$resolved"
      return 0
      ;;
    esac
  done
  return 1
}

ndpi_write_public_key(){
  local output="$1"
  [ -n "$DS_NDPI_ARTIFACT_PUBLIC_KEY_B64" ] || return 1
  printf '%s' "$DS_NDPI_ARTIFACT_PUBLIC_KEY_B64" | base64 -d > "$output.der" 2>/dev/null \
    || return 1
  openssl pkey -pubin -inform DER -in "$output.der" -pubout -out "$output" \
    >/dev/null 2>&1
}

ndpi_manifest_revoked(){
  local manifest="$1" actual digest
  actual="$(sha256sum "$manifest" | awk '{print $1}')"
  for digest in ${DS_NDPI_REVOKED_MANIFESTS//,/ }; do
    [ "$actual" != "$digest" ] || return 0
  done
  return 1
}

verify_ndpi_artifact_bundle(){
  local bundle="$1" module_path="$2" plugin_path="$3"
  local manifest="$bundle/manifest" signature="$bundle/manifest.sig"
  local certificate="$bundle/signing-certificate.crt"
  local work expected_keys key value
  local format artifact_release commit dkms_version source_sha source_epoch os_id os_version architecture
  local kernel iptables_version xtables_version module_file module_sha module_size
  local vermagic_sha sig_id signer_b64 module_key_id plugin_file plugin_sha plugin_size
  local cert_sha manifest_key_id policy_sha actual_vermagic actual_signer actual_sig_id
  local actual_arch actual_iptables

  for value in openssl sha256sum base64 modinfo stat; do have "$value" || return 1; done
  [ -f "$manifest" ] && [ ! -L "$manifest" ] \
    && [ -f "$signature" ] && [ ! -L "$signature" ] \
    && [ -f "$certificate" ] && [ ! -L "$certificate" ] \
    && [ -f "$module_path" ] && [ ! -L "$module_path" ] \
    && [ -f "$plugin_path" ] && [ ! -L "$plugin_path" ] || return 1
  [ "$(wc -l < "$manifest")" = 25 ] || return 1
  [ "$(tail -c 1 "$manifest" | wc -l)" = 1 ] || return 1
  ! grep -q $'\r' "$manifest" || return 1

  work="$(mktemp -d)" || return 1
  if ! ndpi_write_public_key "$work/public.pem"; then rm -rf "$work"; return 1; fi
  if ! openssl dgst -sha256 -verify "$work/public.pem" \
      -signature "$signature" "$manifest" >/dev/null 2>&1; then
    rm -rf "$work"
    return 1
  fi
  if ndpi_manifest_revoked "$manifest"; then rm -rf "$work"; return 1; fi

  expected_keys='format artifact_release ndpi_commit ndpi_dkms_version source_archive_sha256 source_date_epoch os_id os_version_id architecture kernel_release iptables_version xtables_version module_file module_sha256 module_size module_vermagic_sha256 module_sig_id module_signer_b64 module_key_id xtables_file xtables_sha256 xtables_size signing_certificate_sha256 manifest_key_id signing_policy_sha256'
  while IFS='=' read -r key value; do
    [ -n "$key" ] && [ -n "$value" ] && [[ " $expected_keys " = *" $key "* ]] \
      || { rm -rf "$work"; return 1; }
  done < "$manifest"
  for key in $expected_keys; do
    ndpi_manifest_value "$manifest" "$key" >/dev/null \
      || { rm -rf "$work"; return 1; }
  done

  format="$(ndpi_manifest_value "$manifest" format)"
  artifact_release="$(ndpi_manifest_value "$manifest" artifact_release)"
  commit="$(ndpi_manifest_value "$manifest" ndpi_commit)"
  dkms_version="$(ndpi_manifest_value "$manifest" ndpi_dkms_version)"
  source_sha="$(ndpi_manifest_value "$manifest" source_archive_sha256)"
  source_epoch="$(ndpi_manifest_value "$manifest" source_date_epoch)"
  os_id="$(ndpi_manifest_value "$manifest" os_id)"
  os_version="$(ndpi_manifest_value "$manifest" os_version_id)"
  architecture="$(ndpi_manifest_value "$manifest" architecture)"
  kernel="$(ndpi_manifest_value "$manifest" kernel_release)"
  iptables_version="$(ndpi_manifest_value "$manifest" iptables_version)"
  xtables_version="$(ndpi_manifest_value "$manifest" xtables_version)"
  module_file="$(ndpi_manifest_value "$manifest" module_file)"
  module_sha="$(ndpi_manifest_value "$manifest" module_sha256)"
  module_size="$(ndpi_manifest_value "$manifest" module_size)"
  vermagic_sha="$(ndpi_manifest_value "$manifest" module_vermagic_sha256)"
  sig_id="$(ndpi_manifest_value "$manifest" module_sig_id)"
  signer_b64="$(ndpi_manifest_value "$manifest" module_signer_b64)"
  module_key_id="$(ndpi_manifest_value "$manifest" module_key_id)"
  plugin_file="$(ndpi_manifest_value "$manifest" xtables_file)"
  plugin_sha="$(ndpi_manifest_value "$manifest" xtables_sha256)"
  plugin_size="$(ndpi_manifest_value "$manifest" xtables_size)"
  cert_sha="$(ndpi_manifest_value "$manifest" signing_certificate_sha256)"
  manifest_key_id="$(ndpi_manifest_value "$manifest" manifest_key_id)"
  policy_sha="$(ndpi_manifest_value "$manifest" signing_policy_sha256)"
  actual_arch="$(ndpi_architecture 2>/dev/null || true)"
  actual_iptables="$(ndpi_iptables_version 2>/dev/null || true)"

  [ "$format" = ds-guard-xt-ndpi-v1 ] \
    && [ "$artifact_release" = "$DS_NDPI_ARTIFACT_RELEASE" ] \
    && [ "$commit" = "$NDPI_COMMIT" ] \
    && [ "$dkms_version" = "$NDPI_ARTIFACT_DKMS_VERSION" ] \
    && [ "$source_sha" = "$NDPI_SOURCE_ARCHIVE_SHA256" ] \
    && [[ "$source_epoch" =~ ^[0-9]{9,12}$ ]] \
    && [ "$os_id" = "$ID" ] \
    && [ "$os_version" = "${VERSION_ID:-}" ] \
    && [ "$architecture" = "$actual_arch" ] \
    && [ "$kernel" = "$KREL" ] \
    && [ "$iptables_version" = "$actual_iptables" ] \
    && ndpi_safe_atom "$xtables_version" \
    && [ "$module_file" = xt_ndpi.ko ] \
    && [ "$plugin_file" = libxt_ndpi.so ] \
    && [[ "$module_sha" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "$plugin_sha" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "$vermagic_sha" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "$cert_sha" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "$module_key_id" =~ ^[0-9a-f]{64}$ ]] \
    && [[ "$manifest_key_id" =~ ^[0-9a-f]{64}$ ]] \
    && [ "$policy_sha" = "$NDPI_SIGNING_POLICY_SHA256" ] \
    && [[ "$module_size" =~ ^[1-9][0-9]*$ ]] \
    && [[ "$plugin_size" =~ ^[1-9][0-9]*$ ]] \
    && [ "$sig_id" = PKCS#7 ] \
    && [[ "$signer_b64" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] \
    || { rm -rf "$work"; return 1; }

  [ "$(sha256sum "$module_path" | awk '{print $1}')" = "$module_sha" ] \
    && [ "$(sha256sum "$plugin_path" | awk '{print $1}')" = "$plugin_sha" ] \
    && [ "$(stat -c %s "$module_path")" = "$module_size" ] \
    && [ "$(stat -c %s "$plugin_path")" = "$plugin_size" ] \
    && [ "$(openssl x509 -in "$certificate" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" = "$cert_sha" ] \
    || { rm -rf "$work"; return 1; }
  openssl pkey -pubin -in "$work/public.pem" -outform DER > "$work/manifest.der" 2>/dev/null \
    && openssl x509 -in "$certificate" -pubkey -noout 2>/dev/null \
      | openssl pkey -pubin -outform DER > "$work/module.der" 2>/dev/null \
    || { rm -rf "$work"; return 1; }
  [ "$(sha256sum "$work/manifest.der" | awk '{print $1}')" = "$manifest_key_id" ] \
    && [ "$(sha256sum "$work/module.der" | awk '{print $1}')" = "$module_key_id" ] \
    || { rm -rf "$work"; return 1; }

  actual_vermagic="$(modinfo -F vermagic "$module_path" 2>/dev/null || true)"
  actual_sig_id="$(modinfo -F sig_id "$module_path" 2>/dev/null || true)"
  actual_signer="$(modinfo -F signer "$module_path" 2>/dev/null || true)"
  case "$actual_vermagic" in "$KREL "*) ;; *) rm -rf "$work"; return 1;; esac
  [ "$(printf '%s' "$actual_vermagic" | sha256sum | awk '{print $1}')" = "$vermagic_sha" ] \
    && [ "$actual_sig_id" = "$sig_id" ] \
    && [ "$(printf '%s' "$actual_signer" | base64 -w0)" = "$signer_b64" ] \
    || { rm -rf "$work"; return 1; }
  rm -rf "$work"
  return 0
}

NDPI_BUNDLE_FILES="manifest manifest.sig xt_ndpi.ko libxt_ndpi.so signing-certificate.crt"
# One deadline bounds the entire signed-bundle download.
NDPI_FETCH_BUDGET=120

# Download a size-bounded bundle; the caller verifies its signature.
fetch_ndpi_bundle(){
  local architecture iptables_version value base file max_size left deadline
  architecture="$(ndpi_architecture)" || return 1
  iptables_version="$(ndpi_iptables_version)" || return 1
  for value in "$ID" "${VERSION_ID:-}" "$architecture" "$KREL"; do ndpi_safe_atom "$value" || return 1; done
  base="$DS_NDPI_ARTIFACT_BASE_URL/$DS_NDPI_ARTIFACT_RELEASE/$NDPI_COMMIT/$ID/${VERSION_ID}/$architecture/$KREL/iptables-$iptables_version"
  deadline=$((SECONDS + NDPI_FETCH_BUDGET))
  for file in $NDPI_BUNDLE_FILES; do
    case "$file" in
      manifest|signing-certificate.crt) max_size=65536;;
      manifest.sig) max_size=16384;;
      xt_ndpi.ko) max_size=67108864;;
      libxt_ndpi.so) max_size=8388608;;
    esac
    left=$((deadline - SECONDS))
    [ "$left" -gt 0 ] || return 2
    if ! ( ulimit -f $((max_size / 1024 + 1)) && trap '' XFSZ && exec timeout -k 5 "$left" \
        curl --fail --silent --show-error --proto '=https' --proto-redir '=https' \
        --max-redirs 0 --connect-timeout 10 --max-time "$left" --retry 2 \
        --retry-connrefused --retry-max-time "$left" --max-filesize "$max_size" \
        --output "$1/$file" "$base/$file" ) >/dev/null 2>"$1/curl.err"; then
      cat "$1/curl.err" >> "$LOG" 2>/dev/null; rm -f "$1/curl.err"; return 2
    fi
    rm -f "$1/curl.err"
  done
}

# Ключ манифестов — тот самый: расшифрованный DER сверяется с закреплённым sha256
# при каждом запуске, не только при выпуске скрипта.
ndpi_artifact_key_ok(){
  [ "$(printf '%s' "$DS_NDPI_ARTIFACT_PUBLIC_KEY_B64" | base64 -d 2>/dev/null | sha256sum | awk '{print $1}')" \
    = "$NDPI_ARTIFACT_PUBKEY_SHA256" ]
}

# Все xt_ndpi под ядром $1 в тех видах, что подхватывает depmod.
ndpi_module_files(){
  find "/lib/modules/$1" \( -name xt_ndpi.ko -o -name xt_ndpi.ko.gz -o -name xt_ndpi.ko.xz \
    -o -name xt_ndpi.ko.zst \) \( -type f -o -type l \) 2>/dev/null
}

# На время подмены прежние xt_ndpi ядра $1 лежат с хвостом .ds17-aside: такое
# имя depmod не видит, а вернуть файл — одно переименование.
ndpi_aside_files(){
  find "/lib/modules/$1" -name 'xt_ndpi.ko*.ds17-aside' \( -type f -o -type l \) 2>/dev/null
}
ndpi_aside_put(){
  local f
  for f in $(ndpi_module_files "$1"); do mv -f "$f" "$f.ds17-aside" || return 1; done
}

# Своя копия под ядром $1 встала: сборки DKMS этого ядра, прямые копии, которые
# клал stage_dkms, когда dkms отказывал, и всё отложенное подменой уходят
# насовсем. dkms вместе с последней сборкой снимает и регистрацию, а она нужна
# под будущие ядра — при живых исходниках она возвращается.
ndpi_dkms_drop(){
  local k="$1" v f
  if have dkms; then
    for v in $(dkms status -m ndpi -k "$k" 2>/dev/null | grep -F "$k" \
        | sed -nE 's#^ndpi[/,] *([^,: ]+).*#\1#p' | sort -u); do
      dkms remove -m ndpi -v "$v" -k "$k" >>"$LOG" 2>&1 || true
    done
    if [ -f "/usr/src/ndpi-$NDPI_DKMS_VERSION/dkms.conf" ] \
        && ! dkms status -m ndpi -v "$NDPI_DKMS_VERSION" 2>/dev/null | grep -q .; then
      dkms add -m ndpi -v "$NDPI_DKMS_VERSION" >>"$LOG" 2>&1 || true
    fi
  fi
  for f in $(ndpi_module_files "$k") $(ndpi_aside_files "$k"); do
    [ "$f" = "/lib/modules/$k/updates/ds-guard/xt_ndpi.ko" ] || rm -f "$f"
  done
}

# Снять свою копию модуля под ядром $1 вместе с записью о ней.
ndpi_artifact_drop(){
  local k="$1" dir="/lib/modules/$1/updates/ds-guard"
  [ -e "$dir" ] || [ -e "$NDPI_ARTIFACT_STATE/$k" ] || [ -e "$NDPI_ARTIFACT_STATE/.$k.next" ] || return 0
  rm -f "$dir/xt_ndpi.ko" "$dir/xt_ndpi.ko.next" "$dir/xt_ndpi.ko.ds17-aside"
  rmdir "$dir" 2>/dev/null
  rm -rf "$NDPI_ARTIFACT_STATE/$k" "$NDPI_ARTIFACT_STATE/.$k.next"
  depmod -a "$k" >>"$LOG" 2>&1 || true
  return 0
}

# Подмена под ядром $1 не удалась: новая копия уходит, отложенное возвращается
# на место. Своя прежняя копия возвращается, только если $2=1 — модуль был
# загружен, то есть она работала, или до проверки дело не дошло; копию, которая
# и не загружалась, держать незачем.
ndpi_swap_back(){
  local k="$1" f ours="/lib/modules/$1/updates/ds-guard/xt_ndpi.ko"
  rm -f "$ours" "$ours.next"
  for f in $(ndpi_aside_files "$k"); do
    if [ "$f" = "$ours.ds17-aside" ] && [ "$2" != 1 ]; then
      rm -f "$f"; rm -rf "${NDPI_ARTIFACT_STATE:?}/$k"
    else
      mv -f "$f" "${f%.ds17-aside}"
    fi
  done
  rmdir "${ours%/*}" 2>/dev/null
  depmod -a "$k" >>"$LOG" 2>&1 || true
}

# Подмена, оборванная посреди (питание, убитый юнит). Точка невозврата — перенос
# записи о новой копии: до неё — откат к прежнему, после — доделать.
ndpi_aside_settle(){
  local k="$1" plugin
  if [ -n "$(ndpi_aside_files "$k")" ]; then
    if [ -e "$NDPI_ARTIFACT_STATE/.$k.next" ]; then
      log "kernel $k: rolling back an interrupted xt_ndpi swap"
      ndpi_swap_back "$k" 1
      if plugin="$(ndpi_plugin_path)" && [ -e "$plugin.ds17-prev" ]; then mv -f "$plugin.ds17-prev" "$plugin"; fi
    else
      log "kernel $k: completing an interrupted xt_ndpi swap"
      ndpi_dkms_drop "$k"
    fi
  fi
  rm -rf "${NDPI_ARTIFACT_STATE:?}/.$k.next"
  rm -f "/lib/modules/$k/updates/ds-guard/xt_ndpi.ko.next"
}

# Своя копия под ядром $1 по-прежнему заслуживает доверия: подпись закреплённым
# ключом, манифест не отозван, байты модуля и плагина — те, что в нём. Версии ОС
# и iptables берутся из самого манифеста: обновление системы — не повод отзывать
# модуль ядра, а отзыв, чужие байты и другой ключ — повод.
ndpi_artifact_trusted(){
  local k="$1" rec="$NDPI_ARTIFACT_STATE/$1"
  ndpi_artifact_key_ok && ndpi_safe_atom "$k" && [ -d "$rec" ] && [ ! -L "$rec" ] || return 1
  (
    KREL="$k"
    ID="$(ndpi_manifest_value "$rec/manifest" os_id)" \
      && VERSION_ID="$(ndpi_manifest_value "$rec/manifest" os_version_id)" \
      && arch="$(ndpi_manifest_value "$rec/manifest" architecture)" \
      && ipt="$(ndpi_manifest_value "$rec/manifest" iptables_version)" || exit 1
    ndpi_architecture(){ printf '%s' "$arch"; }
    ndpi_iptables_version(){ printf '%s' "$ipt"; }
    verify_ndpi_artifact_bundle "$rec" "/lib/modules/$k/updates/ds-guard/xt_ndpi.ko" "$rec/libxt_ndpi.so"
  )
}

# Своя копия под ядром $1 сверяется с тем, чему этот скрипт доверяет сейчас. Не
# прошла — уходит с диска; из памяти не выгружается (на ней могут стоять
# правила), до перезагрузки работает она. Проверить нечем — не повод отзывать.
# Запись без копии тоже уходит. Звать под build.lock.
ndpi_artifact_recheck(){
  local k="$1" t
  ndpi_aside_settle "$k"
  if [ -e "/lib/modules/$k/updates/ds-guard/xt_ndpi.ko" ]; then
    for t in openssl sha256sum base64 modinfo stat; do have "$t" || return 0; done
    # Проверка пишет ключ и разбор во временный каталог. Если туда не пишется
    # (переполненный tmpfs у Debian 13), отказ значил бы только это — тогда
    # копию не трогаем, повторим в следующий раз.
    t="$(mktemp -d 2>/dev/null)" || return 0
    if ! head -c 65536 /dev/zero > "$t/probe" 2>/dev/null; then rm -rf "$t"; return 0; fi
    rm -rf "$t"
    ndpi_artifact_trusted "$k" && return 0
    warn "kernel $k: signed xt_ndpi no longer passes verification (revoked, altered or another key): removed from disk"
    logger -t ds-guard -p user.warning "kernel $k: signed xt_ndpi failed re-verification and was removed from disk"
  fi
  ndpi_artifact_drop "$k"
}
# Ядра, под которыми есть своя копия, запись о ней или след оборванной подмены.
ndpi_artifact_kernels(){
  local p k
  for p in /lib/modules/*/updates/ds-guard "$NDPI_ARTIFACT_STATE"/*; do
    [ -e "$p" ] || continue
    case "$p" in /lib/modules/*) k="${p#/lib/modules/}"; k="${k%%/*}";; *) k="${p##*/}";; esac
    ndpi_safe_atom "$k" && printf '%s\n' "$k"
  done | sort -u
}
ndpi_artifact_recheck_all(){
  local k
  for k in $(ndpi_artifact_kernels); do ndpi_artifact_recheck "$k"; done
  return 0
}

# Примет ли загруженный xt_ndpi плагин $1. Проверяется исполнением: копия
# плагина в своём каталоге впереди системного, правило с ним — в цепочку, куда
# не ведёт ни один переход. Так срабатывают и сверка версии в самом плагине,
# и проверка размеров в ядре. srcversion тут не годится: у модулей Debian его нет.
ndpi_plugin_fits(){
  local xt t rc=1
  xt="$(ndpi_plugin_path)" && [ -f "$1" ] && t="$(mktemp -d)" || return 1
  if cp "$1" "$t/libxt_ndpi.so"; then
    iptables -w -N DS17_PROBE >/dev/null 2>&1 || iptables -w -F DS17_PROBE >/dev/null 2>&1
    XTABLES_LIBDIR="$t:${xt%/*}" iptables -w -A DS17_PROBE -m ndpi --proto bittorrent -j RETURN >>"$LOG" 2>&1 && rc=0
    iptables -w -F DS17_PROBE >/dev/null 2>&1; iptables -w -X DS17_PROBE >/dev/null 2>&1
  fi
  rm -rf "$t"
  return "$rc"
}
# Плагин $1 встаёт вместо установленного, если он другой и загруженный xt_ndpi
# его принимает. 0 — встал или уже стоит.
ndpi_plugin_adopt(){
  local p
  p="$(ndpi_plugin_path)" && [ -f "$1" ] || return 1
  cmp -s "$1" "$p" && return 0
  lsmod 2>/dev/null | grep -q '^xt_ndpi[[:space:]]' && ndpi_plugin_fits "$1" || return 1
  install -m 0644 "$1" "$p.next" && mv -f "$p.next" "$p" || { rm -f "$p.next"; return 1; }
  log "xtables plugin replaced by $1: the loaded xt_ndpi accepts it"
}
# Модуль ядра $1 загружен, а iptables его не принимает: плагин от другой сборки
# (собранный в git-клоне отказывает модулю из комплекта). Годный берётся из
# записи о своей копии, иначе из исходников DKMS. Предупреждение — раз за загрузку.
ndpi_plugin_repair(){
  local k="$1" s c="" m=/run/ds-guard/plugin-mismatch
  iptables -w -m ndpi --help >/dev/null 2>&1 && { rm -f "$m"; return 0; }
  ndpi_artifact_trusted "$k" && c="$NDPI_ARTIFACT_STATE/$k/libxt_ndpi.so"
  for s in $c "/usr/src/ndpi-$NDPI_DKMS_VERSION/ndpi-netfilter/ipt/libxt_ndpi.so"; do
    ndpi_plugin_adopt "$s" && iptables -w -m ndpi --help >/dev/null 2>&1 || continue
    rm -f "$m"; logger -t ds-guard "kernel $k: xtables plugin taken from $s to match the loaded xt_ndpi"; return 0
  done
  [ -e "$m" ] || logger -t ds-guard -p user.warning "kernel $k: xt_ndpi is loaded, but no plugin at hand fits it"
  : > "$m"; return 1
}

# Install one verified signed bundle under the build lock without unloading a
# running module. Return 0 installed, 2 unavailable, 1 rejected.
ndpi_artifact_install(){
  local k="$1" work rc dir mod rec nrec plugin="" running=0 was_loaded=0 conf_new=0 boot
  ndpi_artifact_key_ok || { warn "embedded nDPI artifact key does not match its pin"; return 1; }
  ndpi_safe_atom "$k" && [ -d "/lib/modules/$k" ] || return 1
  ndpi_artifact_recheck "$k"
  [ "$k" = "$(uname -r)" ] && running=1
  work="$(mktemp -d)" || return 1
  ( KREL="$k"; fetch_ndpi_bundle "$work" )
  rc=$?
  if [ "$rc" != 0 ]; then
    rm -rf "$work"
    if [ "$rc" = 2 ]; then log "kernel $k: no signed xt_ndpi is published or the relay is unreachable"; return 2; fi
    warn "kernel $k: signed xt_ndpi does not apply to this system"; return 1
  fi
  if ! ( KREL="$k"; verify_ndpi_artifact_bundle "$work" "$work/xt_ndpi.ko" "$work/libxt_ndpi.so" ); then
    rm -rf "$work"; warn "kernel $k: published xt_ndpi failed verification"; return 1
  fi
  if [ "$running" = 1 ]; then
    plugin="$(ndpi_plugin_path)" || { rm -rf "$work"; warn "cannot locate the xtables plugin directory"; return 1; }
    if lsmod 2>/dev/null | grep -q '^xt_ndpi[[:space:]]'; then
      was_loaded=1
      if ! ndpi_plugin_fits "$work/libxt_ndpi.so"; then
        rm -rf "$work"; warn "loaded xt_ndpi is another build, it rejects the signed plugin: not replacing it live"; return 1
      fi
    fi
  fi
  dir="/lib/modules/$k/updates/ds-guard"; mod="$dir/xt_ndpi.ko"
  rec="$NDPI_ARTIFACT_STATE/$k"; nrec="$NDPI_ARTIFACT_STATE/.$k.next"
  # Новое сначала ложится рядом со старым: не хватило места — не потеряно ничего.
  rm -rf "$nrec"
  if ! mkdir -p "$nrec" "$dir" \
      || ! cp "$work/manifest" "$work/manifest.sig" "$work/signing-certificate.crt" "$work/libxt_ndpi.so" "$nrec/" \
      || ! install -m 0644 "$work/xt_ndpi.ko" "$mod.next"; then
    rm -rf "$work" "$nrec"; rm -f "$mod.next"; rmdir "$dir" 2>/dev/null
    warn "kernel $k: cannot stage the signed xt_ndpi"; return 1
  fi
  # Файл меняется под загруженным модулем: до перезагрузки в памяти прежний, и
  # status должен это сказать.
  if [ "$was_loaded" = 1 ]; then
    boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
    if [ ! -e "$mod" ] || ! cmp -s "$rec/manifest" "$nrec/manifest" \
        || [ "$(cat "$rec/loaded-before" 2>/dev/null)" = "$boot" ]; then
      printf '%s\n' "$boot" > "$nrec/loaded-before"
    fi
  fi
  if ! ndpi_aside_put "$k" || ! mv -f "$mod.next" "$mod" || ! depmod -a "$k" >>"$LOG" 2>&1; then
    rm -rf "$work" "$nrec"; ndpi_swap_back "$k" 1
    warn "kernel $k: cannot put the signed xt_ndpi in place"; return 1
  fi
  if [ "$running" = 1 ]; then
    [ -e /etc/modules-load.d/xt_ndpi.conf ] || conf_new=1
    rm -f "$plugin.ds17-prev"
    [ ! -e "$plugin" ] || cp -a "$plugin" "$plugin.ds17-prev"
    ndpi_conf
    if ! install -m 0644 "$work/libxt_ndpi.so" "$plugin.next" || ! mv -f "$plugin.next" "$plugin" \
        || ! modprobe xt_ndpi >>"$LOG" 2>&1 || ! iptables -w -m ndpi --help >/dev/null 2>&1; then
      warn "kernel $k: signed xt_ndpi does not work here"
      rm -f "$plugin.next"
      if [ -e "$plugin.ds17-prev" ]; then mv -f "$plugin.ds17-prev" "$plugin"; else rm -f "$plugin"; fi
      [ "$was_loaded" = 1 ] || modprobe -r xt_ndpi >/dev/null 2>&1 || true
      [ "$conf_new" = 0 ] || rm -f /etc/modules-load.d/xt_ndpi.conf /etc/modprobe.d/xt_ndpi.conf
      rm -rf "$work" "$nrec"; ndpi_swap_back "$k" "$was_loaded"; return 1
    fi
    rm -f "$plugin.ds17-prev"
  fi
  # Точка невозврата — запись о новой копии; после неё отложенное уходит насовсем.
  rm -rf "$rec"; mv -f "$nrec" "$rec"
  ndpi_dkms_drop "$k"
  rm -rf "$work"
  [ "$running" = 1 ] || ndpi_plugin_adopt "$rec/libxt_ndpi.so" || log "kernel $k: its plugin is installed after a boot into it"
  ok "kernel $k: signed xt_ndpi in place (manifest $(sha256sum "$rec/manifest" | awk '{print $1}'))"
  return 0
}

# Замок сборки. Повторный вызов при взятом замке ничего не делает: заново
# открытый fd 9 отпустил бы его, и в эту щель вошёл бы хук ядра.
ndpi_lock(){
  [ "${NDPI_LOCK_HELD:-0}" = 1 ] && return 0
  mkdir -p /run/ds-guard && exec 9>/run/ds-guard/build.lock && flock -w "$1" 9 && NDPI_LOCK_HELD=1
}
ndpi_unlock(){ exec 9>&-; NDPI_LOCK_HELD=0; }

fetch_pinned_ndpi(){
  local build_dir="$1" actual_commit archive_sha
  mkdir -p "$build_dir" || return 1
  git -C "$build_dir" init -q || return 1
  git -C "$build_dir" remote add origin "$NDPI_REPO" || return 1
  # Застрявшее соединение рвётся после минуты почти без данных, попытка целиком —
  # через NDPI_GIT_TIMEOUT: у git своего предела нет. Функцию берут и отдельно от
  # скрипта (стенд цепочки поставки), поэтому предел — с запасным значением.
  retry 2 timeout "${NDPI_GIT_TIMEOUT:-600}" git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60 \
    -C "$build_dir" fetch -q --depth 1 origin "$NDPI_COMMIT" || return 1
  actual_commit="$(git -C "$build_dir" rev-parse FETCH_HEAD 2>/dev/null)" || return 1
  [ "$actual_commit" = "$NDPI_COMMIT" ] || { warn "nDPI source commit mismatch"; return 1; }
  archive_sha="$(git -C "$build_dir" archive --format=tar "$NDPI_COMMIT" | sha256sum | awk '{print $1}')"
  [ "$archive_sha" = "$NDPI_SOURCE_ARCHIVE_SHA256" ] || { warn "nDPI source archive digest mismatch"; return 1; }
  # Populate the build tree only after both independent pins have matched.
  git -C "$build_dir" -c core.hooksPath=/dev/null checkout -q --detach "$NDPI_COMMIT" || return 1
  safe_patch_source "$build_dir" || return 1
  # Дальше как у сборщика комплектов: без .git и с датой коммита. С .git
  # configure пишет в модуль и плагин 5.1.0-1-63880be, без него — 5.1.0, как в
  # комплектах. Плагин принимает модуль, только если его версия входит в версию
  # модуля, и длинный отказывал подписанному модулю следующего ядра.
  NDPI_EPOCH="$(git -C "$build_dir" show -s --format=%ct "$NDPI_COMMIT" 2>/dev/null)"
  [[ "$NDPI_EPOCH" =~ ^[0-9]+$ ]] || NDPI_EPOCH=""
  rm -rf "$build_dir/.git"
}

build_ndpi(){
  [ "$MODULES_OK" = 1 ] || { warn "L1 nDPI skipped (container)"; return 1; }
  # 1.7.2 and older registered ndpi/1.0 with AUTOINSTALL="yes". Strip it before
  # anything can fail: the paths below that keep the old module (fetch or build
  # failure) must not leave dpkg's dkms hook building nDPI for the next kernel.
  local f
  for f in /usr/src/ndpi-1.0/dkms.conf /usr/src/ndpi-1.7.*/dkms.conf; do
    [ -f "$f" ] && sed -i '/^AUTOINSTALL=/d' "$f"
  done
  # Замок — до первого modprobe: своя копия, которой больше нельзя доверять
  # (отозвана, подменена, другой ключ), уходит с диска раньше, чем её загрузят.
  ndpi_lock 2700 || warn "a kernel-hook build still holds the lock; continuing"
  ndpi_artifact_recheck_all
  # Re-run aware: was OUR nDPI already working before this run? If a rebuild
  # then fails, we fall back to it so a re-run never breaks a healthy server.
  local had_ndpi=0
  if modprobe xt_ndpi 2>/dev/null && $IPT -m ndpi --help >/dev/null 2>&1; then had_ndpi=1; fi
  [ "$had_ndpi" = 1 ] && log "--- L1: nDPI present: reinstalling (fresh rebuild) ---" || log "--- L1: installing nDPI (xt_ndpi) ---"
  # Сначала подписанный модуль ровно под это ядро: ни заголовков, ни компилятора
  # ему не нужно. Не вышло что угодно — сборка через DKMS, как раньше. DKMS при
  # удаче всё равно остаётся запасным путём под ядра, к которым комплекта не
  # будет: исходники регистрируются без сборки, а если сейчас не получилось,
  # их подготовит хук ядра, когда понадобится.
  if ndpi_artifact_install "$KREL"; then
    ndpi_stage_source || log "DKMS fallback source not registered now: prepared on demand for the next kernel"
    ndpi_unlock
    ok "L1 nDPI installed from the signed module + loaded (bt_hash=32)"
    return 0
  fi
  # Комплект в этот раз не встал (сеть, страница вместо файла), а слой работает
  # на своей копии, которая только что заново прошла проверку: она и остаётся.
  # Менять рабочий модуль на сборку незачем, а без заголовков и нельзя.
  if [ "$had_ndpi" = 1 ] && [ -e "/lib/modules/$KREL/updates/ds-guard/xt_ndpi.ko" ]; then
    ndpi_conf
    ndpi_stage_source || log "DKMS fallback source not registered now: prepared on demand for the next kernel"
    ndpi_unlock
    ok "L1 nDPI: the verified signed module in place is kept"
    return 0
  fi
  ndpi_unlock
  # Kernel toolchain: Clang-built kernels (XanMod / custom) need the LLVM
  # toolchain for the out-of-tree module; a stock GCC kernel uses the default.
  local KMAKE=""
  if grep -qs 'CONFIG_CC_IS_CLANG=y' "/boot/config-$KREL" 2>/dev/null || grep -qi clang /proc/version 2>/dev/null; then
    log "custom Clang-built kernel detected (e.g. XanMod): building module with LLVM=1"
    apt_install clang lld llvm || warn "clang/lld/llvm install failed"
    KMAKE="LLVM=1"
  fi
  apt_install_headers "linux-headers-$KREL" || true
  # Headers that follow the installed kernel flavour, so every NEXT kernel
  # arrives with its headers (images without them lost nDPI after an upgrade).
  install_header_meta
  if [ ! -d "/lib/modules/$KREL/build" ]; then
    # Работает сборка DKMS закреплённой версии: пересобирать нечего, она остаётся.
    if [ "$had_ndpi" = 1 ] && dkms status -m ndpi -v "$NDPI_DKMS_VERSION" -k "$KREL" 2>/dev/null | grep -q installed; then
      ndpi_conf; ok "L1 nDPI: the pinned DKMS build in place is kept (no headers to rebuild it)"; return 0
    fi
    headers_gone_hint; return 1
  fi
  apt_install build-essential git autoconf automake libtool pkg-config libpcap-dev libgcrypt20-dev flex bison libxtables-dev dkms || warn "some nDPI deps failed to install"
  _miss=""; for _b in gcc make dkms pkg-config git; do have "$_b" || _miss="$_miss $_b"; done
  [ -n "$_miss" ] && { warn "nDPI build tools missing:$_miss: L1 skipped (enable universe/base repos)"; return 1; }
  cd /opt || return 1; rm -rf ndpi-build
  fetch_pinned_ndpi /opt/ndpi-build >>"$LOG" 2>&1 || { warn "pinned nDPI source verification failed"; return 1; }
  if ! ( cd /opt/ndpi-build && { [ -z "${NDPI_EPOCH:-}" ] || export SOURCE_DATE_EPOCH="$NDPI_EPOCH"; } \
      && ./autogen.sh && ./configure && make -j2 ) >>"$LOG" 2>&1; then
    ndpi_dkms_failed "$KREL" "libnDPI does not build here"; warn "libnDPI build failed"; return 1
  fi
  ( cd /opt/ndpi-build/ndpi-netfilter && make -j2 $KMAKE EXTRA_CFLAGS="$NDPI_KCFLAGS" ) >>"$LOG" 2>&1
  local KO SO; KO=$(find /opt/ndpi-build -name xt_ndpi.ko|head -1); SO=$(find /opt/ndpi-build -name libxt_ndpi.so|head -1)
  if [ -z "$KO" ] || [ -z "$SO" ]; then
    if [ "$had_ndpi" = 1 ]; then warn "nDPI rebuild did not complete: keeping the existing working module"; ndpi_conf; return 0; fi
    # Хук ядра и проверка при загрузке не будут пересобирать это каждый час.
    ndpi_dkms_failed "$KREL" "xt_ndpi does not build on this kernel"
    warn "L1 nDPI skipped (module could not be built on this kernel)"; return 1
  fi

  stage_dkms "$KO"
  local XTDIR; XTDIR="$(pkg-config --variable=xtlibdir xtables 2>/dev/null || echo /usr/lib/$(uname -m)-linux-gnu/xtables)"
  # Слой работал, а новый плагин загруженный модуль не примет: до перезагрузки
  # остаётся прежний, после неё новый поставит ndpi_ensure.
  if [ "$had_ndpi" = 1 ] && ! ndpi_plugin_fits "$SO"; then log "new xtables plugin waits for a reboot"
  else cp "$SO" "$XTDIR/libxt_ndpi.so" 2>/dev/null; fi
  ndpi_conf
  # Reinstall refreshes the on-disk module (DKMS) + userspace lib; the running
  # module stays loaded (no live churn) and the OUTPUT rule is left to the
  # enforcer (install_enforcer / 5-min timer), so a re-run never drops it.
  modprobe xt_ndpi 2>/dev/null && $IPT -m ndpi --help >/dev/null 2>&1 && { ok "L1 nDPI (re)installed + loaded (bt_hash=32)"; return 0; }
  warn "xt_ndpi built but not loadable: L1 degraded"; return 1
}
stage_dkms(){
  local ko="$1" v f
  # Same lock as the kernel-hook build: a kernel installed meanwhile must not
  # build from a source tree this function is replacing.
  ndpi_lock 2700 || warn "a kernel-hook build still holds the lock; continuing"
  ndpi_dkms_tree /opt/ndpi-build
  dkms status -m ndpi -v "$NDPI_DKMS_VERSION" 2>/dev/null | grep -q . && dkms remove -m ndpi -v "$NDPI_DKMS_VERSION" --all >>"$LOG" 2>&1
  # Подписанная копия под этим ядром уходит только после удачной сборки: пока
  # сборки нет, рабочий модуль — она.
  if dkms add -m ndpi -v "$NDPI_DKMS_VERSION" >>"$LOG" 2>&1 \
      && dkms build -m ndpi -v "$NDPI_DKMS_VERSION" -k "$KREL" >>"$LOG" 2>&1 \
      && ndpi_artifact_drop "$KREL" \
      && dkms install -m ndpi -v "$NDPI_DKMS_VERSION" -k "$KREL" --force >>"$LOG" 2>&1; then
    # Older registrations (the fixed "1.0" of 1.7.2 and before) go only after
    # the new one built: until then they are the working module.
    # dkms 3 prints "ndpi/<ver>, ...", dkms 2.8 (Ubuntu 22.04) "ndpi, <ver>, ...".
    for v in $(dkms status -m ndpi 2>/dev/null | sed -nE 's#^ndpi[/,] *([^,: ]+).*#\1#p' | sort -u); do
      [ "$v" = "$NDPI_DKMS_VERSION" ] || dkms remove -m ndpi -v "$v" --all >>"$LOG" 2>&1
    done
    rm -rf /usr/src/ndpi-1.0
    rm -f "$NDPI_DKMS_FAILED/$KREL"
    ok "DKMS ndpi/$NDPI_DKMS_VERSION installed for $KREL"
  else
    warn "DKMS registration failed: installing the built module directly"
    ndpi_artifact_drop "$KREL"
    for f in $(ndpi_module_files "$KREL"); do rm -f "$f"; done
    mkdir -p "/lib/modules/$KREL/updates/dkms"; cp "$ko" "/lib/modules/$KREL/updates/dkms/"; depmod -a "$KREL"
  fi
  ndpi_unlock
}
# Дерево исходников для DKMS из собранных закреплённых исходников $1.
ndpi_dkms_tree(){
  local src="/usr/src/ndpi-$NDPI_DKMS_VERSION"
  rm -rf "$src"; cp -a "$1" "$src" || return 1
  cat > "$src/ds-dkms-build.sh" <<'DKMS_BUILD'
#!/usr/bin/env bash
set -e
kernelver="$1"
extra=()
if grep -qs 'CONFIG_CC_IS_CLANG=y' "/boot/config-$kernelver" 2>/dev/null || \
   { [ "$kernelver" = "$(uname -r)" ] && grep -qi clang /proc/version 2>/dev/null; }; then
  extra+=(LLVM=1)
fi
exec make -C ndpi-netfilter/src KERNEL_DIR="/lib/modules/$kernelver/build" \
  modules EXTRA_CFLAGS="-std=gnu99 -Wno-error=implicit-function-declaration" "${extra[@]}"
DKMS_BUILD
  chmod 0755 "$src/ds-dkms-build.sh"
  # No AUTOINSTALL line: dkms 3.0.x treats ANY non-empty value (even "no") as
  # yes, and then its kernel hook builds nDPI inside dpkg — a build failure on
  # some future kernel would leave the kernel package half-configured and stop
  # every later apt run. New kernels are prepared by our own hook instead.
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
ndpi_stage_source(){
  # Register the pinned source without building it. Interrupted staging is
  # replaced next run, so /opt cannot accumulate 130 MB work trees.
  local b rc=0 src="$NDPI_STAGE_DIR/src"
  if have dkms && [ -f "/usr/src/ndpi-$NDPI_DKMS_VERSION/dkms.conf" ] \
      && dkms status -m ndpi -v "$NDPI_DKMS_VERSION" 2>/dev/null | grep -q .; then
    return 0
  fi
  apt_install build-essential git autoconf automake libtool pkg-config libpcap-dev libgcrypt20-dev flex bison libxtables-dev dkms \
    || warn "some nDPI deps failed to install"
  for b in gcc make dkms pkg-config git; do have "$b" || { warn "nDPI build tools missing: $b"; return 2; }; done
  # Регистрация без исходников: dkms add поверх неё не пройдёт.
  dkms status -m ndpi -v "$NDPI_DKMS_VERSION" 2>/dev/null | grep -q . \
    && dkms remove -m ndpi -v "$NDPI_DKMS_VERSION" --all >>"$LOG" 2>&1
  rm -rf "$NDPI_STAGE_DIR"; mkdir -p "$NDPI_STAGE_DIR" || return 2
  if ! fetch_pinned_ndpi "$src" >>"$LOG" 2>&1; then
    warn "pinned nDPI source could not be fetched for DKMS"; rc=2
  elif ! timeout "$NDPI_STAGE_BUILD_TIMEOUT" bash -c \
        'cd "$1" && { [ -z "$2" ] || export SOURCE_DATE_EPOCH="$2"; } && ./autogen.sh && ./configure \
        && make -j2 && make -C ndpi-netfilter/ipt' _ "$src" "${NDPI_EPOCH:-}" >>"$LOG" 2>&1 \
      || ! ndpi_dkms_tree "$src" || ! dkms add -m ndpi -v "$NDPI_DKMS_VERSION" >>"$LOG" 2>&1; then
    warn "pinned nDPI source could not be prepared for DKMS"; rc=1
  else
    ok "pinned nDPI source registered in DKMS (ndpi/$NDPI_DKMS_VERSION, not built)"
  fi
  rm -rf "$NDPI_STAGE_DIR"
  return "$rc"
}
# Сборка DKMS под ядро $1 не вышла ($2 — что именно). Запоминается вместе с
# версией исходников: следующая попытка под это ядро — через сутки, а не каждый
# час, и предупреждение в журнал — один раз, а не на каждой попытке.
ndpi_dkms_failed(){
  local f="$NDPI_DKMS_FAILED/$1"
  if [ "$(cat "$f" 2>/dev/null)" = "$NDPI_DKMS_VERSION" ]; then
    log "kernel $1: $2 (again)"
  else
    logger -t ds-guard -p user.warning "kernel $1: $2"
  fi
  mkdir -p "$NDPI_DKMS_FAILED" && printf '%s\n' "$NDPI_DKMS_VERSION" > "$f"
}
ndpi_dkms_kernel(){
  # Build only the pinned version: an older registered ndpi would not match the
  # plugin installed by a signed bundle. $2 bounds the build, $3 the dpkg-lock
  # wait, and $4 the build-lock wait.
  local k="$1" limit="$2" wait="$3" v="$NDPI_DKMS_VERSION" st plugin rc failed="$NDPI_DKMS_FAILED/$1"
  if [ "$(cat "$failed" 2>/dev/null)" = "$v" ] && [ -n "$(find "$failed" -mmin -1440 2>/dev/null)" ]; then
    log "kernel $k: ndpi/$v did not build here within the last day: DKMS not retried yet"; return 1
  fi
  if [ ! -d "/lib/modules/$k/build" ]; then
    if RELEASE_UPGRADE_IN_PROGRESS=1 apt-get $APT_NET_OPTS -o DPkg::Lock::Timeout="$wait" -y -q \
        install "linux-headers-$k" >>"$LOG" 2>&1; then
      apt-mark auto "linux-headers-$k" >/dev/null 2>&1 || true
    fi
  fi
  [ -d "/lib/modules/$k/build" ] || { logger -t ds-guard "kernel $k: no headers for a DKMS build of xt_ndpi"; return 1; }
  ndpi_lock "$4" || return 1
  ndpi_stage_source
  rc=$?
  case "$rc" in
    0) ;;
    1) ndpi_dkms_failed "$k" "pinned nDPI source does not build here"; return 1;;
    *) logger -t ds-guard "kernel $k: pinned nDPI source cannot be prepared for DKMS now"; return 1;;
  esac
  # Своя копия уходит только после удачной сборки.
  st="$(dkms status -m ndpi -v "$v" -k "$k" 2>/dev/null | grep -F "$k")"
  case "$st" in
    *installed*) ;;
    *built*) ndpi_artifact_drop "$k"; timeout 10m dkms install -m ndpi -v "$v" -k "$k" --force >>"$LOG" 2>&1;;
    *) timeout "$limit" dkms build -m ndpi -v "$v" -k "$k" >>"$LOG" 2>&1 && ndpi_artifact_drop "$k" \
         && timeout 10m dkms install -m ndpi -v "$v" -k "$k" --force >>"$LOG" 2>&1;;
  esac || { ndpi_dkms_failed "$k" "DKMS could not build xt_ndpi"; return 1; }
  rm -f "$failed"
  # После установки из комплекта, сорвавшейся на загрузке, плагина может не быть.
  if [ "$k" = "$(uname -r)" ] && plugin="$(ndpi_plugin_path)" && [ ! -e "$plugin" ] \
      && [ -f "/usr/src/ndpi-$v/ndpi-netfilter/ipt/libxt_ndpi.so" ]; then
    install -m 0644 "/usr/src/ndpi-$v/ndpi-netfilter/ipt/libxt_ndpi.so" "$plugin" || true
  fi
  return 0
}
# xt_ndpi под ядро $1 — сейчас, а не при перезагрузке: подписанный модуль, потом
# DKMS. Для нового ядра это хук (ds-guard-kprep@): пока его заголовки ещё в
# архиве, не внутри dpkg, работающий модуль и правила не трогаются. Сюда же
# ensure отдаёт работающее ядро, у которого модуля нет, — тогда модуль ещё и
# загружается, а правила утверждаются сразу, не дожидаясь таймера.
ndpi_kprep(){
  local k="${1:-}" running=0
  ndpi_safe_atom "$k" && [ -d "/lib/modules/$k" ] || return 0
  # ds-guard 2.x installed over this one prepares kernels itself.
  [ -e /etc/systemd/system/ssh.service.d/zz-ds-guard.conf ] && return 0
  [ "$k" = "$(uname -r)" ] && running=1
  ndpi_lock 2400 || return 0
  ndpi_artifact_recheck_all
  # Под ядро, в которое ещё не загружались, проверенная своя копия уже готова.
  if [ "$running" = 0 ] && [ -e "/lib/modules/$k/updates/ds-guard/xt_ndpi.ko" ]; then
    ndpi_unlock; log "kernel $k: signed xt_ndpi already in place"; return 0
  fi
  if ndpi_artifact_install "$k"; then
    ndpi_unlock
    logger -t ds-guard "kernel $k: signed xt_ndpi placed"
  else
    # Заголовки ставятся без замка сборки: dpkg ещё может держать свой.
    ndpi_unlock
    if ! ndpi_dkms_kernel "$k" 40m 1800 2400; then ndpi_unlock; return 0; fi
    ndpi_unlock
    logger -t ds-guard "kernel $k: xt_ndpi built (DKMS)"
    if [ "$running" = 1 ]; then
      ndpi_conf
      modprobe -q xt_ndpi 2>/dev/null \
        || { logger -t ds-guard -p user.warning "kernel $k: xt_ndpi built by DKMS does not load"; return 0; }
    fi
  fi
  [ "$running" = 0 ] || systemctl --no-block start ds-guard-apply.service >/dev/null 2>&1 || true
  return 0
}
# Загрузка и таймер (ds-guard-apply.service, каждые 5 минут): у работающего ядра
# должен быть xt_ndpi. Сама проверка короткая: своя копия, которой больше нельзя
# доверять, снимается с диска раньше любой загрузки, а если модуля нет —
# подписанный модуль и DKMS готовит ds-guard-kprep@ этого ядра, в фоне и со
# своим пределом времени, чтобы таймер правил не стоял за сборкой. Попытка —
# раз в час, а не на каждом проходе.
ndpi_ensure(){
  local k busy=0
  k="$(uname -r)"
  mkdir -p /run/ds-guard
  # Замок занят — его держит хук ядра или установщик: копии они проверяют сами,
  # а модуль, может быть, как раз встаёт. Тогда без метки и предупреждения —
  # следующий проход через 5 минут.
  if ndpi_lock 0; then ndpi_artifact_recheck_all; ndpi_unlock; else busy=1; fi
  if modprobe -q xt_ndpi 2>/dev/null; then
    rm -f /run/ds-guard/l1-missing /run/ds-guard/build-failed
    if [ "$busy" = 0 ] && ndpi_lock 0; then ndpi_plugin_repair "$k"; ndpi_unlock; fi
    return 0
  fi
  [ "$busy" = 0 ] || return 0
  # The marker goes down BEFORE the attempt, so a killed attempt also leaves it.
  if [ -n "$(find /run/ds-guard/build-failed -mmin -60 2>/dev/null)" ]; then
    echo "$k" > /run/ds-guard/l1-missing; return 0
  fi
  [ -e /run/ds-guard/l1-missing ] || logger -t ds-guard -p user.warning \
    "nDPI layer inactive: no loadable xt_ndpi for kernel $k; preparing it in the background"
  echo "$k" > /run/ds-guard/l1-missing
  touch /run/ds-guard/build-failed
  systemctl --no-block start "ds-guard-kprep@$(systemd-escape "$k").service" >/dev/null 2>&1 || true
  return 0
}
ndpi_conf(){ echo 'options xt_ndpi bt_hash_size=32 bt_hash_timeout=1200' > /etc/modprobe.d/xt_ndpi.conf; echo 'xt_ndpi' > /etc/modules-load.d/xt_ndpi.conf; }
install_header_meta(){
  # Exactly the version of the installed kernel metapackage, never newer: on
  # Ubuntu the image and headers metapackages are tied, and a newer headers
  # metapackage would pull a new kernel onto a client server as a side effect.
  # Then unattended-upgrades updates both together and the next kernel comes
  # with its headers. If that exact version has left the archive, nothing is
  # installed: the kernel hook fetches headers when the next kernel arrives.
  local img meta ver
  for img in $(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-image-*' 2>/dev/null \
      | awk '$1=="ii"{print $2}' | grep -vE '^linux-image-(unsigned-)?[0-9]'); do
    meta="${img/linux-image-/linux-headers-}"
    ver="$(dpkg-query -W -f='${Version}' "$img" 2>/dev/null)"
    [ -n "$ver" ] || continue
    if dpkg-query -W -f='${db:Status-Abbrev}' "$meta" 2>/dev/null | grep -q '^ii'; then
      log "headers already follow $img via $meta"; continue
    fi
    if apt-cache madison "$meta" 2>/dev/null | awk -F'|' '{gsub(/ /,"",$2); print $2}' | grep -qxF "$ver"; then
      apt_install_headers "$meta=$ver" && log "headers follow $img via $meta=$ver" || log "could not install $meta=$ver"
    else
      log "no $meta=$ver in the archive: the kernel hook will fetch headers for the next kernel"
    fi
  done
  return 0
}
headers_gone_hint(){
  # The archive keeps headers only for recent kernels. Never reboot a client
  # server ourselves: tell what to do instead.
  local r nk=""
  for r in $(ls -1 /lib/modules 2>/dev/null); do
    [ "$r" = "$KREL" ] && continue
    [ -s "/boot/vmlinuz-$r" ] || continue
    [ -s "/boot/initrd.img-$r" ] || [ -s "/boot/initramfs-$r.img" ] || continue
    dpkg --compare-versions "$r" gt "$KREL" 2>/dev/null || continue
    [ -z "$nk" ] || dpkg --compare-versions "$r" gt "$nk" || continue
    nk="$r"
  done
  if [ -n "$nk" ]; then
    warn "headers for running kernel $KREL are no longer available; kernel $nk is installed: reboot, then run ./ds-guard again"
  else
    warn "headers for running kernel $KREL are no longer available: apt upgrade, reboot, then run ./ds-guard again"
  fi
}

# ============================ L2: Suricata (UDP only) =======================
# На Debian 12 (образ Hetzner) Suricata есть только в bookworm-backports, а её
# libhtp2 apt по приоритету берёт из основной ветки, где версия старше нужной:
# установка падает на «held broken packages». Кандидата из backports ставим
# вместе с зависимостями той же ветки (-t), приоритеты системы не трогаем.
suricata_install(){
  local cand suite
  cand=$(LC_ALL=C apt-cache policy suricata 2>/dev/null | awk '/Candidate:/{print $2; exit}')
  suite=$(apt-cache madison suricata 2>/dev/null \
    | awk -F' *[|] *' -v c="$cand" '$2==c{split($3,a," "); split(a[2],b,"/"); print b[1]; exit}')
  case "$suite" in
    *-backports)
      log "suricata $cand comes from $suite: installing with its dependencies from $suite"
      retry 3 apt-get $APT_NET_OPTS -o DPkg::Lock::Timeout=300 -y -q -t "$suite" install suricata >>"$LOG" 2>&1;;
    *) apt_install suricata;;
  esac
}

setup_suricata(){
  [ "$NFQ_OK" = 1 ] || { warn "L2 Suricata skipped (no NFQUEUE)"; return 1; }
  log "--- L2: Suricata (NFQUEUE, UDP) ---"
  have suricata || suricata_install || { warn "suricata install failed: L2 skipped"; return 1; }
  mkdir -p /etc/suricata/rules; write_ds_p2p_rules
  sed -i "s|^\\([[:space:]]*\\)- interface: eth0|\\1- interface: $WAN|" /etc/suricata/suricata.yaml 2>/dev/null
  sed -i 's|^default-rule-path:.*|default-rule-path: /etc/suricata/rules|' /etc/suricata/suricata.yaml 2>/dev/null
  sed -i 's|^\([[:space:]]*\)- suricata.rules|\1- ds-p2p.rules|' /etc/suricata/suricata.yaml 2>/dev/null
  grep -q 'ds-p2p.rules' /etc/suricata/suricata.yaml 2>/dev/null || sed -i 's|^rule-files:.*|rule-files:\n  - ds-p2p.rules|' /etc/suricata/suricata.yaml 2>/dev/null
  mkdir -p /etc/systemd/system/suricata.service.d
  cat > /etc/systemd/system/suricata.service.d/nfqueue.conf <<'OVR'
[Service]
Type=simple
PIDFile=
ExecStart=
ExecStart=/usr/bin/suricata -q 0 -q 1 -c /etc/suricata/suricata.yaml
Restart=on-failure
RestartSec=3
OVR
  systemctl daemon-reload; systemctl reset-failed suricata 2>/dev/null
  suricata -T -c /etc/suricata/suricata.yaml >>"$LOG" 2>&1 || return 1
  systemctl enable suricata >>"$LOG" 2>&1; retry 2 systemctl restart suricata; sleep 2
  [ "$(systemctl is-active suricata)" = active ] && { ok "L2 Suricata active (NFQUEUE UDP)"; return 0; }
  warn "suricata not active: L2 degraded"; return 1
}
write_ds_p2p_rules(){
cat > /etc/suricata/rules/ds-p2p.rules <<'RULES'
# DoubleServers focused P2P / torrent detection (fed UDP-only via NFQUEUE).
drop tcp any any -> any any (msg:"DS P2P BitTorrent handshake"; flow:established; content:"|13|BitTorrent protocol"; depth:20; fast_pattern; classtype:policy-violation; sid:9000001; rev:1;)
drop udp any any -> any any (msg:"DS P2P BitTorrent DHT query (id)"; content:"d1:ad2:id20:"; fast_pattern; classtype:policy-violation; sid:9000002; rev:1;)
drop udp any any -> any any (msg:"DS P2P DHT get_peers"; content:"9:get_peers"; fast_pattern; classtype:policy-violation; sid:9000003; rev:1;)
drop udp any any -> any any (msg:"DS P2P DHT announce_peer"; content:"13:announce_peer"; fast_pattern; classtype:policy-violation; sid:9000004; rev:1;)
drop udp any any -> any any (msg:"DS P2P DHT find_node"; content:"9:find_node"; fast_pattern; classtype:policy-violation; sid:9000005; rev:1;)
drop udp any any -> any any (msg:"DS P2P UDP tracker connect"; content:"|00 00 04 17 27 10 19 80|"; depth:8; offset:0; fast_pattern; classtype:policy-violation; sid:9000006; rev:1;)
drop http any any -> any any (msg:"DS P2P HTTP tracker announce"; flow:to_server; http.uri; content:"info_hash="; fast_pattern; content:"peer_id="; classtype:policy-violation; sid:9000007; rev:1;)
drop http any any -> any any (msg:"DS P2P HTTP tracker scrape"; flow:to_server; http.uri; content:"info_hash="; content:"/scrape"; classtype:policy-violation; sid:9000008; rev:1;)
drop http any any -> any any (msg:"DS P2P torrent client User-Agent"; flow:to_server; http.user_agent; pcre:"/(uTorrent|BitTorrent\/|Transmission\/|libtorrent|Azureus|qBittorrent|Deluge|rtorrent|BitComet)/i"; classtype:policy-violation; sid:9000009; rev:1;)
drop tcp any any -> any any (msg:"DS P2P BitTorrent LSD BT-SEARCH"; content:"BT-SEARCH "; depth:10; fast_pattern; classtype:policy-violation; sid:9000010; rev:1;)
drop udp any any -> any any (msg:"DS P2P BitTorrent LSD BT-SEARCH (udp)"; content:"BT-SEARCH "; depth:10; fast_pattern; classtype:policy-violation; sid:9000011; rev:1;)
drop udp any any -> any any (msg:"DS P2P BitTorrent uTP bencode"; content:"d1:rd2:id20:"; fast_pattern; classtype:policy-violation; sid:9000012; rev:1;)
alert tcp any any -> any any (msg:"DS P2P magnet/info_hash in stream"; content:"xt=urn:btih:"; fast_pattern; classtype:policy-violation; sid:9000013; rev:1;)
drop udp any any -> any any (msg:"DS P2P DHT ping (a id)"; content:"1:q4:ping"; fast_pattern; classtype:policy-violation; sid:9000014; rev:1;)
RULES
}

# ============================ L3: exact domain block (IPv4) ================
setup_domains(){
  local list="$STATE_DIR/domains.txt" labels="$STATE_DIR/domain-labels.txt" raw="$STATE_DIR/domains.raw" next="$STATE_DIR/domains.next.$$" d normalized
  : > "$raw"
  if [ "$DS_PACKETSDK" = 1 ]; then
    packetsdk_ioc_domains >> "$raw"; printf '%s\n' packetsdk > "$labels.next" \
      && chmod 0644 "$labels.next" && mv -f "$labels.next" "$labels" || { rm -f "$labels.next"; return 1; }
  else rm -f "$labels" "$labels.next"; fi
  [ "$DS_TORRENT" = 1 ] && torrent_site_domains >> "$raw"
  [ -n "$DS_DOMAINS" ] && printf '%s\n' "$DS_DOMAINS" | tr ', ' '\n' | sed '/^$/d' >> "$raw"
  : > "$next"
  while IFS= read -r d; do
    if normalized="$(normalize_domain "$d")"; then printf '%s\n' "$normalized" >> "$next"
    else warn "ignored invalid domain name: $d"; fi
  done < "$raw"
  rm -f "$raw"; LC_ALL=C sort -u "$next" -o "$next" || { rm -f "$next"; return 1; }
  [ -s "$next" ] || { rm -f "$next" "$list"; return 0; }
  chmod 0644 "$next" && mv -f "$next" "$list" || { rm -f "$next"; return 1; }
  [ "$STRING_OK" = 1 ] || { rm -f "$list" "$labels"; warn "L3 domain block skipped (no -m string)"; return 1; }
  ok "L3 domain block list: $(tr '\n' ' ' <"$list")"
  return 0
}

setup_conntrack_accounting(){
  [ -s "$STATE_DIR/domains.txt" ] || return 0
  local p made=0 o="$STATE_DIR/conntrack-owner.env" n="$CONNTRACK_SYSCTL.next.$$"
  modprobe nf_conntrack >/dev/null 2>&1 && modprobe xt_ndpi >/dev/null 2>&1 \
    && $IPT -m ndpi --help >/dev/null 2>&1 && $IPT -m connbytes -h >/dev/null 2>&1 \
    || { warn "domain matcher prerequisites unavailable"; return 1; }
  p="$(sysctl -n net.netfilter.nf_conntrack_acct 2>/dev/null)"; case "$p" in 0|1);; *) warn "conntrack accounting unavailable"; return 1;; esac
  if [ ! -e "$o" ]; then printf 'CONNTRACK_ACCT_PREVIOUS=%q\n' "$p" >"$o"&&chmod 0600 "$o"||return 1; made=1; fi
  if sysctl -q -w net.netfilter.nf_conntrack_acct=1 >/dev/null \
    && printf '%s\n' '# ds-guard xt_connbytes' 'net.netfilter.nf_conntrack_acct = 1' >"$n"&&chmod 0644 "$n"&&mv -f "$n" "$CONNTRACK_SYSCTL"; then
    ok "conntrack packet accounting enabled"; return 0
  fi
  rm -f "$n"; [ "$made" = 0 ] || { sysctl -q -w "net.netfilter.nf_conntrack_acct=$p" >/dev/null||true; rm -f "$o"; }
  warn "cannot enable conntrack accounting"; return 1
}

# ============================ enforcer + self-heal ==========================
NDPI_HELPER_VARS="VERSION NDPI_REPO NDPI_COMMIT NDPI_SOURCE_ARCHIVE_SHA256 NDPI_DKMS_VERSION NDPI_KCFLAGS STATE_DIR SBIN APT_NET_OPTS PKG_FAMILY NDPI_ARTIFACT_DKMS_VERSION NDPI_SIGNING_POLICY_SHA256 NDPI_ARTIFACT_PUBKEY_SHA256 DS_NDPI_ARTIFACT_PUBLIC_KEY_B64 DS_NDPI_ARTIFACT_RELEASE DS_NDPI_REVOKED_MANIFESTS DS_NDPI_ARTIFACT_BASE_URL NDPI_ARTIFACT_STATE NDPI_DKMS_FAILED NDPI_STAGE_DIR NDPI_GIT_TIMEOUT NDPI_STAGE_BUILD_TIMEOUT NDPI_HELPER NDPI_BUNDLE_FILES NDPI_FETCH_BUDGET c_g c_y c_r c_c c_0"
NDPI_HELPER_FUNCS="_flog log ok warn err have retry apt_install ndpi_safe_atom ndpi_manifest_value ndpi_architecture ndpi_iptables_version ndpi_plugin_path ndpi_write_public_key ndpi_manifest_revoked verify_ndpi_artifact_bundle fetch_ndpi_bundle ndpi_artifact_key_ok ndpi_module_files ndpi_dkms_drop ndpi_aside_files ndpi_aside_put ndpi_artifact_drop ndpi_swap_back ndpi_aside_settle ndpi_artifact_trusted ndpi_artifact_recheck ndpi_artifact_kernels ndpi_artifact_recheck_all ndpi_plugin_fits ndpi_plugin_adopt ndpi_plugin_repair ndpi_artifact_install ndpi_lock ndpi_unlock ndpi_conf fetch_pinned_ndpi ndpi_dkms_tree ndpi_stage_source ndpi_dkms_failed ndpi_dkms_kernel ndpi_kprep ndpi_ensure"
write_ndpi_helper(){
  local v
  {
    printf '#!/usr/bin/env bash\n'
    printf '# ds-guard %s: xt_ndpi под новое ядро и при загрузке — подписанный модуль, потом DKMS.\n' "$VERSION"
    printf '# Собран установщиком из его же функций: править установщик, а не этот файл.\n'
    printf 'set -u\nexport DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1\n'
    for v in $NDPI_HELPER_VARS; do printf '%s=%q\n' "$v" "${!v}"; done
    printf 'LOG=/var/log/ds-guard-ndpi.log\nLAST_WARN=""\n'
    printf '[ "$(stat -c %%s "$LOG" 2>/dev/null || echo 0)" -lt 1048576 ] || mv -f "$LOG" "$LOG.1" 2>/dev/null\n'
    printf 'ID=$(. /etc/os-release 2>/dev/null; printf %%s "${ID:-}")\n'
    printf 'VERSION_ID=$(. /etc/os-release 2>/dev/null; printf %%s "${VERSION_ID:-}")\n'
    # shellcheck disable=SC2086
    declare -f $NDPI_HELPER_FUNCS
  } > "$NDPI_HELPER.next" && chmod 0644 "$NDPI_HELPER.next" && mv -f "$NDPI_HELPER.next" "$NDPI_HELPER"
}

install_enforcer(){
  write_ndpi_helper || warn "cannot write $NDPI_HELPER"
  cat > "$SBIN/ds-guard-ensure.sh" <<ENS
#!/usr/bin/env bash
# Boot/timer check; missing modules are prepared in the background.
set -u
[ "$DOMAIN_REQUESTED$MODULES_OK" = 11 ] || exit 0
. "$NDPI_HELPER" || exit 0
ndpi_ensure
exit 0
ENS
  cat > "$SBIN/ds-guard-kprep.sh" <<KPREP
#!/usr/bin/env bash
# Prepare xt_ndpi for a new kernel: signed module, then DKMS.
set -u
. "$NDPI_HELPER" || exit 0
ndpi_kprep "\${1:-}"
exit 0
KPREP
  for hookdir in /etc/kernel/postinst.d /etc/kernel/header_postinst.d; do
    if [ "$DOMAIN_REQUESTED$MODULES_OK" != 11 ]; then rm -f "$hookdir/zz-ds-guard"; continue; fi
    mkdir -p "$hookdir"
    cat > "$hookdir/zz-ds-guard" <<'HOOK'
#!/bin/sh
# ds-guard: queue the xt_ndpi build for the new kernel; never fail dpkg.
case "${1:-}" in [!A-Za-z0-9]*|*[!A-Za-z0-9._+~-]*|'') exit 0;; esac
systemctl --no-block start "ds-guard-kprep@$(systemd-escape "$1").service" >/dev/null 2>&1 || true
exit 0
HOOK
    chmod 0755 "$hookdir/zz-ds-guard"
  done
  if [ "$DOMAIN_REQUESTED$MODULES_OK" = 11 ]; then
    mkdir -p /etc/kernel/postrm.d
    cat > /etc/kernel/postrm.d/zz-ds-guard <<'POSTRM'
#!/bin/sh
# Drop our module for a removed kernel; never fail dpkg.
k="${1:-}"
case "$k" in [!A-Za-z0-9]*|*[!A-Za-z0-9._+~-]*|'') exit 0;; esac
case "${DEB_MAINT_PARAMS:-remove}" in remove*|purge*) ;; *) exit 0;; esac
d="/lib/modules/$k/updates/ds-guard"
rm -f "$d/xt_ndpi.ko" "$d/xt_ndpi.ko.next" "$d/xt_ndpi.ko.ds17-aside" 2>/dev/null
find "/lib/modules/$k" -name 'xt_ndpi.ko*.ds17-aside' -delete 2>/dev/null
rmdir "$d" "/lib/modules/$k/updates" 2>/dev/null
rm -rf "/etc/ds-guard/ds17-artifact/$k" "/etc/ds-guard/ds17-artifact/.$k.next" "/etc/ds-guard/ds17-dkms-failed/$k" 2>/dev/null
exit 0
POSTRM
    chmod 0755 /etc/kernel/postrm.d/zz-ds-guard
  else
    rm -f /etc/kernel/postrm.d/zz-ds-guard
  fi
  cat > "$SBIN/ds-guard-apply.sh" <<APPLY
#!/usr/bin/env bash
# Re-assert egress protection above UFW/Docker rules.
set -u
IPT="iptables -w"
NIC="\$(ip -4 route show default 2>/dev/null | awk '/default/{print \$5; exit}')"
[ -n "\$NIC" ] || exit 0
LIST=$STATE_DIR/domains.txt
LABELS=$STATE_DIR/domain-labels.txt
mkdir -p /run/ds-guard; exec 9>/run/ds-guard/apply.lock; flock -w 60 9 || exit 0
FWD=FORWARD
if \$IPT -S DOCKER-USER >/dev/null 2>&1 && \$IPT -C FORWARD -j DOCKER-USER 2>/dev/null; then FWD=DOCKER-USER; fi
OTHER=""; [ "\$FWD" = DOCKER-USER ] && OTHER=FORWARD
delc(){ local c=\$1; shift; while \$IPT -C "\$c" "\$@" 2>/dev/null; do \$IPT -D "\$c" "\$@" || return 1; done; }
torrent_rules(){
  [ "${DS_TORRENT}" = 1 ] || return 0
  modprobe -q xt_ndpi 2>/dev/null || true
  R_NFQ="-o \$NIC -p udp -m conntrack --ctstate NEW -j NFQUEUE --queue-balance 0:1 --queue-bypass"
  R_NDPI="-o \$NIC -m ndpi --proto bittorrent -j DROP"
  for _i in 1 2 3 4 5; do \$IPT -m ndpi --help >/dev/null 2>&1 && break; modprobe -q xt_ndpi 2>/dev/null; sleep 1; done
  NDPI_OK=0; \$IPT -m ndpi --help >/dev/null 2>&1 && NDPI_OK=1
  delc OUTPUT \$R_NFQ; command -v suricata >/dev/null 2>&1 && \$IPT -I OUTPUT 1 \$R_NFQ
  [ -n "\$OTHER" ] && [ "\$NDPI_OK" = 1 ] && delc \$OTHER \$R_NDPI
  for CH in OUTPUT \$FWD; do
    if [ "\$NDPI_OK" = 1 ]; then delc \$CH \$R_NDPI; \$IPT -I \$CH 1 \$R_NDPI; fi
  done
  if [ "\$NDPI_OK" != 1 ]; then
    mkdir -p /run/ds-guard; uname -r > /run/ds-guard/l1-missing
    logger -t ds-guard -p user.warning "nDPI rule not asserted: xt_ndpi is not available on \$(uname -r)"
  fi
}

# --- L3 exact DNS/TLS-SNI/HTTP-Host block (IPv4) ---
dnswire(){ local d="\$1" l x out=""; local IFS=. a=(); read -r -a a <<<"\$d"; for l in "\${a[@]}"; do printf -v x '%02x' "\${#l}"; out="\$out|\$x|\$l"; done; printf '%s|00|' "\$out"; }
labelwire(){ local x; printf -v x '%02x' "\${#1}"; printf '|%s|%s' "\$x" "\$1"; }
emitgroups(){
  local kind="\$1" file="\$2" d e body="" candidate prefix suffix
  prefix='/(^|\\.)('; [ "\$kind" = fqdn ] && suffix=')\$/' || suffix=')(\\.|\$)/'
  while IFS= read -r d; do
    [ -n "\$d" ] || continue; e="\${d//./\\\\.}"
    [ -n "\$body" ] && candidate="\${prefix}\${body}|\${e}\${suffix}" || candidate="\${prefix}\${e}\${suffix}"
    if [ "\${#candidate}" -ge 127 ]; then
      [ -n "\$body" ] || return 1; printf '%s%s%s\n' "\$prefix" "\$body" "\$suffix"
      body="\$e"; candidate="\${prefix}\${body}\${suffix}"; [ "\${#candidate}" -lt 127 ] || return 1
    else [ -n "\$body" ] && body="\${body}|\${e}" || body="\$e"; fi
  done < "\$file"
  [ -z "\$body" ] || printf '%s%s%s\n' "\$prefix" "\$body" "\$suffix"
}
DA=0; DR=DS_DOMAINS; DS=$STATE_DIR/domain-generation.env
ce(){ \$IPT -S "\$1" >/dev/null 2>&1; }; nr(){ \$IPT -S "\$1" 2>/dev/null|grep -c "^-A \$1 "||true; }
cd(){ ce "\$1"||return 0; \$IPT -F "\$1" >/dev/null 2>&1&&\$IPT -X "\$1" >/dev/null 2>&1; }
gd(){ cd "\$1"&&cd "\$1_D"&&cd "\$1_W"; }; df(){ logger -t ds-guard -p user.warning "domain policy apply failed"; torrent_rules; exit 1; }
if [ -s "\$LIST" ] || [ -s "\$LABELS" ]; then
  \$IPT -m string -h >/dev/null 2>&1 && \$IPT -m multiport -h >/dev/null 2>&1 \
    && \$IPT -m ndpi --help >/dev/null 2>&1 && \$IPT -m connbytes -h >/dev/null 2>&1 \
    && [ "\$(sysctl -n net.netfilter.nf_conntrack_acct 2>/dev/null)" = 1 ] || df
  ce "\$DR" || \$IPT -N "\$DR" >/dev/null 2>&1 || df
  F="\$(\$IPT -S "\$DR" 2>/dev/null|sed -n "s/^-A \$DR //p"|sed -n '1p')"
  case "\$F" in
    '-j DS_DOM_A') O=DS_DOM_A; N=DS_DOM_B;;
    '-j DS_DOM_B') O=DS_DOM_B; N=DS_DOM_A;;
    *) O=; N=DS_DOM_A;;
  esac
  if [ -n "\$O" ]; then while [ "\$(nr "\$DR")" -gt 1 ]; do \$IPT -D "\$DR" 2||df; done; fi
  gd "\$N"||df
  \$IPT -N "\$N" >/dev/null 2>&1&&\$IPT -N "\${N}_D" >/dev/null 2>&1&&\$IPT -N "\${N}_W" >/dev/null 2>&1||{ gd "\$N" >/dev/null 2>&1; df; }
  SW=0; P=$STATE_DIR/domain-patterns.txt.next.\$\$; SN="\$DS.next.\$\$"
  PH="\$({ cat "\$LIST"; printf '.\n'; cat "\$LABELS"; }|sha256sum|cut -d' ' -f1)"
  da(){
    rm -f "\$P" "\$SN"; [ "\$SW" = 1 ]||gd "\$N" >/dev/null 2>&1; df
  }
  add(){ \$IPT -A "\$@"||da; }
  : >"\$P"||da; emitgroups fqdn "\$LIST" >"\$P"||da
  [ ! -s "\$LABELS" ]||emitgroups label "\$LABELS" >>"\$P"||da
  DN=0; HN="\$(grep -c . "\$P"||true)"
  add "\$N" -p udp --dport 53 -j "\${N}_D"; add "\$N" -p tcp --dport 53 -j "\${N}_D"
  add "\$N" -p tcp -m multiport --dports 80,443 -j "\${N}_W"; add "\$N" -p udp --dport 443 -j "\${N}_W"
  while IFS= read -r d; do
    [ -n "\$d" ]||continue; q="\$(dnswire "\$d")"; add "\${N}_D" -m string --from 0 --to 512 --hex-string "\$q" --algo kmp --icase -j DROP; DN=\$((DN+1))
  done < "\$LIST"
  if [ -s "\$LABELS" ]; then while IFS= read -r d; do
    [ -n "\$d" ]||continue; q="\$(labelwire "\$d")"; add "\${N}_D" -m string --from 0 --to 512 --hex-string "\$q" --algo kmp --icase -j DROP; DN=\$((DN+1))
  done < "\$LABELS"; fi
  add "\${N}_W" -m connbytes --connbytes 33: --connbytes-mode packets --connbytes-dir original -j RETURN
  while IFS= read -r r; do [ -n "\$r" ]&&add "\${N}_W" -m ndpi --proto all --host "\$r" -j DROP; done <"\$P"
  if [ -n "\$O" ]; then \$IPT -R "\$DR" 1 -j "\$N"||da
  elif [ "\$(nr "\$DR")" -gt 0 ]; then \$IPT -I "\$DR" 1 -j "\$N"||da
  else \$IPT -A "\$DR" -j "\$N"||da; fi
  SW=1; while [ "\$(nr "\$DR")" -gt 1 ]; do \$IPT -D "\$DR" 2||da; done
  chmod 0644 "\$P"&&mv -f "\$P" $STATE_DIR/domain-patterns.txt||da
  printf 'ACTIVE=%s\nDNS_RULES=%s\nHOST_RULES=%s\nPOLICY_SHA=%s\n' "\$N" "\$DN" "\$HN" "\$PH" >"\$SN"&&chmod 0600 "\$SN"&&mv -f "\$SN" "\$DS"||da
  rm -f "\$P"; [ -z "\$O" ]||gd "\$O"||df; DA=1
fi

# --- L1/L2 torrent ---
torrent_rules
# Preserve an existing top-level domain jump so timer repair has no gap.
ensure_domain_jump(){
  local c="\$1" first n want="-A \$1 -o \$NIC -j \$DR"
  first="\$(\$IPT -S "\$c" 2>/dev/null | grep "^-A \$c " | sed -n '1p')"
  [ "\$first" = "\$want" ] || \$IPT -I "\$c" 1 -o "\$NIC" -j "\$DR" || return 1
  while [ "\$(\$IPT -S "\$c" 2>/dev/null | grep -Fxc -- "\$want")" -gt 1 ]; do
    n="\$(\$IPT -S "\$c" 2>/dev/null | awk -v w="\$want" '/^-A /{i++; if(\$0==w)n=i} END{print n}')"
    [ "\${n:-0}" -gt 1 ] && \$IPT -D "\$c" "\$n" || return 1
  done
}
if [ "\$DA" = 1 ]; then
  for CH in OUTPUT \$FWD; do ensure_domain_jump "\$CH" || df; done
  [ -z "\$OTHER" ] || delc "\$OTHER" -o "\$NIC" -j "\$DR" || df
else
  [ -z "\$OTHER" ] || delc "\$OTHER" -o "\$NIC" -j "\$DR" || df
  for CH in OUTPUT \$FWD; do delc "\$CH" -o "\$NIC" -j "\$DR" || df; done
  cd "\$DR"||df; gd DS_DOM_A||df; gd DS_DOM_B||df; rm -f "\$DS" $STATE_DIR/domain-patterns.txt
fi
exit 0
APPLY
  chmod +x "$SBIN/ds-guard-ensure.sh" "$SBIN/ds-guard-apply.sh" "$SBIN/ds-guard-kprep.sh"
  cat > /etc/systemd/system/ds-guard.service <<'SVC'
[Unit]
Description=DoubleServers VPS Guard - anti-torrent + packetsdk block
After=network-online.target suricata.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=2700
Environment=NEEDRESTART_SUSPEND=1
ExecStartPre=-/usr/local/sbin/ds-guard-ensure.sh
ExecStart=/usr/local/sbin/ds-guard-apply.sh
[Install]
WantedBy=multi-user.target
SVC
  cat > /etc/systemd/system/ds-guard-apply.service <<'ASVC'
[Unit]
Description=DoubleServers VPS Guard - re-assert egress rules (idempotent)
After=network-online.target suricata.service ds-guard.service
[Service]
Type=oneshot
TimeoutStartSec=2700
Environment=NEEDRESTART_SUSPEND=1
ExecStartPre=-/usr/local/sbin/ds-guard-ensure.sh
ExecStart=/usr/local/sbin/ds-guard-apply.sh
ASVC
  cat > /etc/systemd/system/ds-guard.timer <<'TMR'
[Unit]
Description=DoubleServers VPS Guard - periodic rule re-assert (self-heal vs firewall reloads)
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Unit=ds-guard-apply.service
[Install]
WantedBy=timers.target
TMR
  cat > /etc/systemd/system/ds-guard-kprep@.service <<'KSVC'
[Unit]
Description=DoubleServers VPS Guard - prepare xt_ndpi for kernel %I
[Service]
Type=oneshot
Nice=10
TimeoutStartSec=5h
Environment=NEEDRESTART_SUSPEND=1
ExecStart=/usr/local/sbin/ds-guard-kprep.sh %I
KSVC
  systemctl daemon-reload
  local k
  if [ "$DOMAIN_REQUESTED$MODULES_OK" = 11 ]; then
    for k in $(ls -1 /lib/modules 2>/dev/null); do
      [ -s "/boot/vmlinuz-$k" ] && dpkg --compare-versions "$k" gt "$KREL" 2>/dev/null || continue
      systemctl --no-block start "ds-guard-kprep@$(systemd-escape "$k").service" >>"$LOG" 2>&1 \
        && log "kernel $k: xt_ndpi preparation queued in the background"
    done
  fi
  systemctl enable --now ds-guard.service >>"$LOG" 2>&1
  systemctl enable --now ds-guard.timer >>"$LOG" 2>&1
  systemctl start ds-guard-apply.service >>"$LOG" 2>&1 || true
  ok "enforcer + self-heal (5-min timer) installed (reboot & firewall-reload safe)"
}

# ============================ status / verify / uninstall ===================
status(){
  local IPT="iptables -w"
  echo "== ds-guard status =="
  echo "WAN: $(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')"
  echo "xt_ndpi: loaded=$(lsmod 2>/dev/null|grep -c '^xt_ndpi') bt_hash=$(cat /sys/module/xt_ndpi/parameters/bt_hash_size 2>/dev/null)"
  echo "xt_ndpi for $(uname -r): $(ndpi_module_origin "$(uname -r)")"
  if ! modinfo -k "$(uname -r)" xt_ndpi >/dev/null 2>&1 || [ -e /run/ds-guard/l1-missing ]; then
    echo "nDPI: module missing for running kernel $(uname -r): L1 OFF (see journalctl -t ds-guard)"
  fi
  echo "suricata: $(systemctl is-active suricata 2>/dev/null)  ds-guard: $(systemctl is-active ds-guard 2>/dev/null)"
  echo "domains blocked: $(tr '\n' ' ' </etc/ds-guard/domains.txt 2>/dev/null)"
  local ch; for ch in OUTPUT FORWARD DOCKER-USER; do
    $IPT -S "$ch" >/dev/null 2>&1 || continue
    echo "$ch rules:"; $IPT -S "$ch" 2>/dev/null | grep -iE 'ndpi|NFQUEUE|DS_DOMAINS' | sed 's/^/  /'
  done
  local dc; for dc in DS_DOM_A_D DS_DOM_A_W DS_DOM_B_D DS_DOM_B_W; do
    $IPT -L "$dc" -n -v 2>/dev/null | grep -i drop | sed 's/^/  domblk: /'
  done
}
# Откуда модуль под ядром $1: подписанный комплект (sha256 манифеста) или DKMS.
# Смотрит на сами файлы и проверяет копию заново, а не верит записи. Если файл
# сменили под загруженным модулем, до перезагрузки в памяти прежний — так и сказано.
ndpi_module_origin(){
  local k="$1" files n rec="$NDPI_ARTIFACT_STATE/$1" sha boot
  files="$(ndpi_module_files "$k")"
  n="$(printf '%s' "$files" | grep -c .)"
  if [ "$n" = 0 ]; then echo "none"; return 0; fi
  if [ "$n" -gt 1 ]; then echo "CONFLICT: $n xt_ndpi modules:" $files; return 0; fi
  case "$files" in
    "/lib/modules/$k/updates/ds-guard/xt_ndpi.ko")
      if ! ndpi_artifact_trusted "$k"; then
        echo "signed artifact path, but it no longer passes verification (removed at the next pass)"; return 0
      fi
      sha="$(sha256sum "$rec/manifest" | awk '{print $1}')"
      boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
      if [ -n "$boot" ] && [ "$(cat "$rec/loaded-before" 2>/dev/null)" = "$boot" ]; then
        echo "on disk: signed artifact, manifest sha256 $sha; in memory: the module loaded before it, until a reboot"
      else
        echo "signed artifact, manifest sha256 $sha"
      fi;;
    */updates/dkms/*) echo "dkms ($files)";;
    *) echo "other ($files)";;
  esac
}
in_both(){  # rule text present in OUTPUT and in the forward chain in use
  local IPT="iptables -w" fwd=FORWARD
  $IPT -S DOCKER-USER >/dev/null 2>&1 && $IPT -C FORWARD -j DOCKER-USER 2>/dev/null && fwd=DOCKER-USER
  $IPT -S OUTPUT | grep -q -- "$1" && $IPT -S "$fwd" | grep -q -- "$1"
}
domain_policy_ok(){
  local IPT="iptables -w" n f=FORWARD a d h p q e r c x=0 v=()
  n="$(ip -4 route show default 2>/dev/null|awk '/default/{print $5;exit}')"; [ -n "$n" ] || return 1
  $IPT -m ndpi --help >/dev/null 2>&1 || return 1
  $IPT -S DOCKER-USER >/dev/null 2>&1 && $IPT -C FORWARD -j DOCKER-USER 2>/dev/null && f=DOCKER-USER
  [ "$(sysctl -n net.netfilter.nf_conntrack_acct 2>/dev/null)" = 1 ] || return 1
  mapfile -t v < <(sed -n 's/^[A-Z_]*=//p' "$STATE_DIR/domain-generation.env" 2>/dev/null); [ "${#v[@]}" = 4 ] || return 1
  a="${v[0]}"; d="${v[1]}"; h="${v[2]}"; p="${v[3]}"; [[ "$d$h" =~ ^[0-9]+$ ]]&&[[ "$p" =~ ^[0-9a-f]{64}$ ]]||return 1
  q="$({ cat "$STATE_DIR/domains.txt"; printf '.\n'; cat "$STATE_DIR/domain-labels.txt"; }|sha256sum|cut -d' ' -f1)"; [ "$p" = "$q" ]||return 1
  case "$a" in DS_DOM_A|DS_DOM_B);; *) return 1;; esac
  for c in OUTPUT "$f"; do [ "$($IPT -S "$c" 2>/dev/null|grep -Fxc -- "-A $c -o $n -j DS_DOMAINS")" = 1 ]||return 1; done
  r="$($IPT -S DS_DOMAINS 2>/dev/null|grep '^-A DS_DOMAINS '||true)"; [ "$r" = "-A DS_DOMAINS -j $a" ]||return 1
  [ "$($IPT -S "$a" 2>/dev/null|grep -c "^-A $a ")" = 4 ]||return 1
  $IPT -C "$a" -p udp --dport 53 -j "${a}_D" 2>/dev/null&&$IPT -C "$a" -p tcp --dport 53 -j "${a}_D" 2>/dev/null \
    &&$IPT -C "$a" -p tcp -m multiport --dports 80,443 -j "${a}_W" 2>/dev/null&&$IPT -C "$a" -p udp --dport 443 -j "${a}_W" 2>/dev/null||return 1
  e="$({ cat "$STATE_DIR/domains.txt" "$STATE_DIR/domain-labels.txt" 2>/dev/null||true; }|grep -c .||true)"; [ "$d" = "$e" ]||return 1
  r="$($IPT -S "${a}_D" 2>/dev/null|grep "^-A ${a}_D "||true)"; [ "$(printf %s "$r"|grep -c -- '-m string .* -j DROP$')" = "$d" ]||return 1
  [ "$($IPT -S "${a}_W" 2>/dev/null|grep -c "^-A ${a}_W ")" = $((h+1)) ]&&$IPT -C "${a}_W" -m connbytes --connbytes 33: --connbytes-mode packets --connbytes-dir original -j RETURN 2>/dev/null||return 1
  r="$($IPT -S "${a}_W" 2>/dev/null|grep "^-A ${a}_W "|sed -n '1p')"; [[ "$r" =~ ^-A\ ${a}_W\ -m\ connbytes\ --connbytes\ 33(:[0-9]*)?\ --connbytes-mode\ packets\ --connbytes-dir\ original\ -j\ RETURN$ ]]||return 1
  [ -s "$STATE_DIR/domain-patterns.txt" ]||return 1
  while IFS= read -r r; do [ -n "$r" ]||continue; $IPT -C "${a}_W" -m ndpi --proto all --host "$r" -j DROP 2>/dev/null||return 1; x=$((x+1)); done < "$STATE_DIR/domain-patterns.txt"
  [ "$x" = "$h" ]
}
verify(){
  local IPT="iptables -w" s=0 t=0
  log "--- verify ---"
  if [ "$DS_TORRENT" = 1 ]; then
    t=$((t+1)); in_both 'ndpi --proto bittorrent' && { s=$((s+1)); ok "nDPI rule present (own + routed traffic)"; } || warn "nDPI rule ABSENT"
    t=$((t+1)); systemctl is-active --quiet suricata && { s=$((s+1)); ok "suricata active"; } || warn "suricata not active"
  fi
  if [ "$DOMAIN_REQUESTED" = 1 ]; then
    t=$((t+1)); [ -s "$STATE_DIR/domains.txt" ] && domain_policy_ok && { s=$((s+1)); ok "exact domain block active"; } || warn "domain-block incomplete"
  fi
  log "verify: $s/$t layers confirmed"
  VERIFY_S=$s; VERIFY_T=$t
}
uninstall(){
  log "=== ds-guard uninstall ==="
  systemctl disable --now ds-guard.timer ds-guard-apply.service ds-guard.service suricata 2>/dev/null
  local IPT="iptables -w" ch n
  ds_hook_no(){
    $IPT -S "$1" 2>/dev/null | awk -v c="$1" '$1=="-A"&&$2==c{p++;if($3=="-o"&&((NF==6&&$5=="-j"&&$6=="DS_DOMAINS")||(NF==10&&$5=="-m"&&$6=="ndpi"&&$7=="--proto"&&$8=="bittorrent"&&$9=="-j"&&$10=="DROP")||(NF==15&&$5=="-p"&&$6=="udp"&&$7=="-m"&&$8=="conntrack"&&$9=="--ctstate"&&$10=="NEW"&&$11=="-j"&&$12=="NFQUEUE"&&$13=="--queue-balance"&&$14=="0:1"&&$15=="--queue-bypass")))n=p}END{if(n)print n}'
  }
  for ch in OUTPUT FORWARD DOCKER-USER; do
    $IPT -S "$ch" >/dev/null 2>&1 || continue
    # Delete only the three exact managed rule forms, independent of old NIC.
    while n="$(ds_hook_no "$ch")"; do
      case "$n" in '') break;; *[!0-9]*) die "unsafe DS_DOMAINS rule number in $ch";; esac
      $IPT -D "$ch" "$n" 2>/dev/null || die "cannot remove ds-guard hook from $ch"
    done
    [ -z "$(ds_hook_no "$ch")" ] || die "ds-guard hook remains in $ch"
  done
  for ch in DS_DOMAINS DS_DOM_A DS_DOM_B DS_DOM_A_D DS_DOM_A_W DS_DOM_B_D DS_DOM_B_W; do
    $IPT -F "$ch" 2>/dev/null; $IPT -X "$ch" 2>/dev/null
  done
  rm -f "$STATE_DIR/domains.txt" "$STATE_DIR/domain-labels.txt" "$STATE_DIR/domain-labels.txt.next" "$STATE_DIR/domain-generation.env" "$STATE_DIR/domain-patterns.txt"
  if [ -r "$STATE_DIR/conntrack-owner.env" ]; then
    . "$STATE_DIR/conntrack-owner.env"
    case "${CONNTRACK_ACCT_PREVIOUS:-}" in 0|1) sysctl -q -w "net.netfilter.nf_conntrack_acct=$CONNTRACK_ACCT_PREVIOUS" >/dev/null || true;; esac
  fi
  rm -f "$CONNTRACK_SYSCTL" "$STATE_DIR/conntrack-owner.env"
  # Свои копии модуля — по самим файлам под /lib/modules и по записям; отложенное
  # оборванной подменой (сборки DKMS) возвращается на место.
  local k
  for k in $(ndpi_artifact_kernels); do ndpi_swap_back "$k" 0; ndpi_artifact_drop "$k"; done
  rm -rf "$NDPI_ARTIFACT_STATE" "$NDPI_DKMS_FAILED" "$NDPI_STAGE_DIR"
  rm -f "$SBIN"/ds-guard-*.sh /etc/systemd/system/ds-guard.service /etc/systemd/system/ds-guard-apply.service /etc/systemd/system/ds-guard.timer \
    /etc/systemd/system/ds-guard-kprep@.service /etc/systemd/system/suricata.service.d/nfqueue.conf \
    /etc/kernel/postinst.d/zz-ds-guard /etc/kernel/header_postinst.d/zz-ds-guard /etc/kernel/postrm.d/zz-ds-guard \
    /etc/modules-load.d/xt_ndpi.conf /etc/modprobe.d/xt_ndpi.conf
  systemctl daemon-reload
  ok "uninstalled (packages left; 'dkms remove ndpi --all' per version to purge module)"
  success
  echo "Packages are left installed; to purge the module: dkms status ndpi, then dkms remove ndpi/<version> --all."
  exit 0
}

# ============================ main ==========================================
# Выше этой строки — только присваивания и функции: сборщик комплектов
# подключает тот текст у себя. Всё исполняемое — отсюда.
