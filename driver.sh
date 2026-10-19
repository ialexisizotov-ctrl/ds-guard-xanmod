#!/usr/bin/env bash
set -uo pipefail
cd /usr/local/lib/ds-guard-safe || exit 1
. ./vendor-library.sh
. ./safe-overrides.sh
DS_TXN="$2"
LOG="$DS_TXN/install.log"
preflight
case "$1" in
  prepare)
    build_ndpi || exit 1
    ;;
  load)
    modprobe xt_ndpi || exit 1
    iptables -w 5 -m ndpi --help >/dev/null || exit 1
    ;;
  plugin-check)
    plugin=$(ndpi_plugin_path) || exit 1
    ndpi_plugin_fits "$plugin" || exit 1
    ;;
  apply)
    STRING_OK=0; iptables -w 5 -m string -h >/dev/null 2>&1 && STRING_OK=1
    NFQ_OK=0; modprobe nfnetlink_queue && NFQ_OK=1
    setup_suricata || exit 1
    setup_domains || exit 1
    setup_conntrack_accounting || exit 1
    install_enforcer || exit 1
    verify
    [ "$VERIFY_T" -gt 0 ] && [ "$VERIFY_T" = "$VERIFY_S" ] || exit 1
    ;;
  verify)
    verify
    [ "$VERIFY_T" -gt 0 ] && [ "$VERIFY_T" = "$VERIFY_S" ] || exit 1
    ;;
  *) exit 64;;
esac
