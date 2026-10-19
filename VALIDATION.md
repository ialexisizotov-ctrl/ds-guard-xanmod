# Validation of the development snapshot

No production release is published yet. `bootstrap.sh` intentionally refuses
installation until its release archive digest is pinned after acceptance.

The isolated Ubuntu 24.04 test VM booted
`7.0.12-x64v2-dsg1-xanmod1`. The exact module build ID matched the loaded module;
the livepatch transition completed, and all three local layers passed.
Synthetic BitTorrent DHT packets were classified and dropped, the Suricata test
signature blocked a synthetic packet, an allowed DNS lookup succeeded, and a
blocked DNS lookup was denied. No real torrent traffic was generated.

A deliberately failing application health check triggered scoped rollback.
Previously active services and their files recovered; unrelated firewall rules
were preserved. The payload tests passed again, and a subsequent installation
completed successfully. A separate SIGKILL test killed the whole installer
control group: systemd OnFailure recovery restored the transaction, left no
worker processes, and the payload tests passed afterward.

Cold-boot persistence and the 7.2 runtime gate are still being tested.
The 7.2 module compiles, but compilation alone is not runtime acceptance.
The development compatibility list includes the candidate so it can be tested;
it must not be treated as an accepted release matrix.

Offline checks: 10 compatibility/preservation/listener tests, 768 actual
hostname-formatter cases under ASan/UBSan, and 16,640 legacy bounded-copy cases
under ASan/UBSan. Exact pinned-source patch application, repeat application and
refusal of unexpected source changes were also checked.

`kernel-stage.sh` is an experimental, separately tested preparation step. It
stages image, headers and an exact module alongside existing kernels, with
bounded CPU/RAM/time, checksum checks and temporary kernel-hook suppression.
It does not reboot or select the candidate for boot. It requires an existing
saved GRUB fallback and rejects foreign DKMS driver migrations. Automatic
kernel activation is not yet implemented. In particular, GRUB environments on
some RAID layouts cannot clear a one-shot boot selection before Linux starts.

These bounded tests do not establish arbitrary-kernel compatibility, IPv6
filtering, peak-load performance, or uninterrupted long-term operation.
