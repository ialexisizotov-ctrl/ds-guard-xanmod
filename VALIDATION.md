# Validation of v1.7.11-dsg1

The installer archive is pinned by SHA-256 in the release bootstrap.
Acceptance was performed sequentially on five production machines.
Production addresses, credentials and configurations are excluded from this repository.

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

Cold-boot persistence passed for both custom XanMod 7.0 and 7.2 kernels,
including exact loaded-module identity and all three filtering layers after
both services became active. The 7.2 VM also passed the intentional health-check
failure, scoped rollback, traffic after rollback and a repeated installation.
An initial 7.0 probe made while the services were still starting did not pass;
these results do not claim filtering is ready before service startup completes.
Ubuntu 6.8.0-147 also passed runtime filtering, intentional health-check
failure and scoped rollback, repeated installation, and cold-boot persistence.
One allowed-DNS probe timed out during a wider resolver interruption; that
failed result is retained. A separate retry and the latest package test passed.

The first production canary on the custom XanMod 7.0 kernel passed five actual
VPN payload checks before and five after installation, all three filtering
layers, strict public-site TLS, exact protected firewall tables and rule order,
routes, policy rules, configuration hashes and container identities. Its previous
kernels remain installed. No kernel faults were found in the bounded window.
A second XanMod 7.0 machine and an Ubuntu 22.04 / 6.8.0-87 machine also passed
actual VPN, three filtering layers and strict public TLS. The latter uses a
module built with its exact Ubuntu 22.04 headers/compiler and retains its kernel.
On the second XanMod machine, preservation is qualified: an existing private
service reconciler removed two obsolete draining rules; six kernel-generated
IPv6 link-local routes appeared. A Docker null/empty-DNS serialization change
required a narrow reconciler compatibility fix. Its unrelated private-service
topology warning remains outside filtering acceptance.
Two additional production machines on the custom XanMod 7.2 kernel passed
five actual VPN checks before and five after installation, all three filtering
layers, strict public-site TLS, exact unrelated firewall rules, configuration
hashes and container identities. On each, the kernel-generated link-local
address of the recreated virtual ifb0 interface changed with its MAC; other
routes and traffic-shaping parameters were preserved. No new kernel fault or
failed service was observed in their bounded acceptance windows.
The Ubuntu 22.04 machine took approximately six minutes to return over SSH
after reboot; the precise cause of the delay was not established. Its existing
RAID-monitor failure and the second XanMod 7.0 machine's pre-existing network
wait-online failure are not represented as repaired by this installer.

Offline checks: 11 compatibility/preservation/listener tests, 768 actual
hostname-formatter cases under ASan/UBSan, and 16,640 legacy bounded-copy cases
under ASan/UBSan. Exact pinned-source patch application, repeat application and
refusal of unexpected source changes were also checked.

`kernel-stage.sh` is a separately tested preparation step. It
stages image, headers and an exact module alongside existing kernels, with
bounded CPU/RAM/time, checksum checks and temporary kernel-hook suppression.
Reviewed Linux crypto/netfilter module renames are resolved against the target
configuration and replacement modules; missing hardware drivers still stop
preparation. It does not reboot or select the candidate for boot. It requires an existing
saved GRUB fallback and rejects foreign DKMS driver migrations. Automatic
kernel activation is not yet implemented. In particular, GRUB environments on
some RAID layouts cannot clear a one-shot boot selection before Linux starts.

These bounded tests do not establish arbitrary-kernel compatibility, IPv6
filtering, peak-load performance, or uninterrupted long-term operation.
