# Same reviewed NFQUEUE setup, with release of the initial-install hold only
# after the configuration test. Existing installed Suricata keeps its behavior.
setup_suricata(){
  [ "$NFQ_OK" = 1 ] || { warn "L2 Suricata skipped (no NFQUEUE)"; return 1; }
  log "--- L2: Suricata (NFQUEUE, UDP) ---"
  have suricata || suricata_install || { warn "suricata install failed: L2 skipped"; return 1; }
  mkdir -p /etc/suricata/rules; write_ds_p2p_rules
  sed -i "s|^\([[:space:]]*\)- interface: eth0|\1- interface: $WAN|" /etc/suricata/suricata.yaml 2>/dev/null
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
  chmod 0644 /etc/systemd/system/suricata.service.d/nfqueue.conf || return 1
  systemctl daemon-reload; systemctl reset-failed suricata 2>/dev/null
  suricata -T -c /etc/suricata/suricata.yaml >>"$LOG" 2>&1 || return 1
  python3 "$DS_TXN/transaction.py" suricata-release "$DS_TXN" >>"$LOG" 2>&1 || return 1
  systemctl enable suricata >>"$LOG" 2>&1; retry 2 systemctl restart suricata; sleep 2
  [ "$(systemctl is-active suricata)" = active ] && { ok "L2 Suricata active (NFQUEUE UDP)"; return 0; }
  warn "suricata not active: L2 degraded"; return 1
}
