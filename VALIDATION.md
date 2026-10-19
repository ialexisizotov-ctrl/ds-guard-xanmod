# Allocator repair candidate — not a production release

The previous `v1.7.11-dsg1` is withdrawn. Its short acceptance windows missed
delayed KFENCE reports in the upstream realloc callback. Historical observations
remain in HISTORICAL_DSG1_VALIDATION.md and do not approve this candidate.

The actual original callback reproducibly fails ASan when growing 2048 bytes to
4096 bytes. The patched callback passed 794 ASan/UBSan cases, including growth,
shrinkage, calloc overflow, allocation/metadata failures and metadata cleanup.
Seventy-three compatibility, preservation, ownership, recovery, package-gate,
selection, restoration and boot-fallback tests pass, with no skipped tests in
the isolated root-capable local check. The compatibility
gate now refuses activation after an existing kernel fault in the current boot.

Modules compile for all four listed kernel/OS pairs. The Ubuntu 22.04 build
uses an isolated official Ubuntu 22.04 container, GCC 12.3.0 and exact
6.8.0-87.88~22.04.1 headers. No production source tree is overwritten.

The final native allocator harness passed 686 cases on each of three isolated
VM kernels: Ubuntu 6.8.0-147, custom XanMod 7.0 and custom XanMod 7.2. It uses
the actual kernel krealloc/XArray/vmalloc implementation, including atomic
packet context and a vmalloc allocation larger than kmalloc's limit. KFENCE
sampling was set to 1 ms in the isolated VMs only.

Completed isolated TLS traffic checks:
- 6.8.0-147-generic: 600 strict local TLS sessions; certificate 14316 DER bytes; KFENCE interval 1 ms; kernel faults 0; cleanup True; passed True. Module SHA-256 `a0fbde3481b0c36f5269c6a9d9c23a63a1d8a2250fdd20fb95222f21b19d2454`.
- 7.0.12-x64v2-dsg1-xanmod1: 600 strict local TLS sessions; certificate 14316 DER bytes; KFENCE interval 1 ms; kernel faults 0; cleanup True; passed True. Module SHA-256 `ece7def533a032fe3edc292e0be58d30b4cc5a6a58018ca942c453a5e59e8822`.
- 7.2.9-x64v3-dsg1-xanmod1: 600 strict local TLS sessions; certificate 14316 DER bytes; KFENCE interval 1 ms; kernel faults 0; cleanup True; passed True. Module SHA-256 `b899f08aa1865084c1b855238a2d1428ceb93889a940fd0279a1678b54683ee7`.
- 6.8.0-87-generic: 600 strict local TLS sessions; certificate 14316 DER bytes; KFENCE interval 1 ms; kernel faults 0; cleanup True; passed True. Module SHA-256 `ea53ae99f1b3bfed0de20a83230bed25654585f15185dff2bc46616baa8a892d`.

The final candidate passed repeated installation on custom XanMod 7.0. An
intentional failing application-health command triggered rollback: scoped files,
previously active services and foreign firewall rules were verified, followed
by successful three-layer payload checks. The final 6.8.0-147 / 7.0 / 7.2
binaries were checked after a new boot with matching loaded ELF build-id. The
Ubuntu 22.04 / 6.8.0-87 binary passed fresh installation and a subsequent cold
boot, matching loaded identity and all three filtering layers again. The first
cold-boot probe ran before service readiness and failed; that original result
is retained. A separate readiness-aware probe passed after startup completed. Ubuntu
22.04 VM preparation initially missed wireless-regdb; that dependency was
installed before the kernel boot and module acceptance. No production system
was used for this repair's build or runtime validation.

The corrected module has not been reaccepted on production. Existing production
nDPI packet matching remains held after the old allocator fault; independent
Suricata/DNS filtering was retained. No new ready-to-install release is approved.
Longer observation, production-specific rollback/boot review and actual
application-path acceptance remain required before that status changes.

## Reversible setup and network profile

The Russian setup interface has separate full, kernel-only, tuning-only, guard,
plan, status, disable and removal modes. Kernel selection uses the pinned tested
catalog, OS, CPU intersection and known loaded-driver exclusions. It does not
reboot, change the saved boot entry or schedule unattended kernel upgrades.

The following full-install lifecycle observations concern the earlier rc1 code;
the package and recovery corrections below require separate updated acceptance.
On an isolated Ubuntu 24.04 VM, fresh full installation and repeated installation
passed local payload checks. Disable, repeated disable, verified resume and full
removal preserved the immutable first baseline, original package versions,
files, sysctls, boot choice, unrelated firewall rules and an unrelated file.
A subsequent cold boot confirmed no nDPI module or managed hooks remained.
Tuning-only installation/removal separately restored original file contents,
mode and group, sysctls, packages and service state without installing guard.
Manual content and ownership changes were refused instead of overwritten.

On Ubuntu 22.04, network-profile apply, explicit rollback, intentional failing
health command and timeout recovery passed. Timeout recovery stops the worker
control group before restoring state; three-layer payload checks passed again.

An initial helper-variable shadowing bug was fixed. Two test-harness failures
were preserved: sysctl whitespace normalization and expecting a temporary test
firewall rule to survive an earlier reboot. Independent baseline comparisons
passed after correcting those assertions. Stock Ubuntu loaded vga16fb/vgastate
even in headless QEMU; the XanMod binaries lack these drivers. The compatibility
gate is retained, automatic policy falls back to Ubuntu and explicit XanMod
refuses. Cleanup of a partial unaccepted kernel stage preserved original packages
and boot selection. These results do not cover arbitrary hardware or legacy
vendor installs that lack a trustworthy original-state journal.


Kernel-only preparation from an already running custom XanMod 7.0 to custom
XanMod 7.2 passed in a separate no-VGA fixture. No nDPI file or service was
installed; the running kernel and saved GRUB selection were preserved. Status
reported the prepared-but-not-running kernel. Removal restored the exact initial
package set and removed only the newly prepared kernel; the original boot
selection remained unchanged. The first assertion compared stripped command
output to a newline-terminated GRUB capture and failed; independent normalized
readback and subsequent removal passed. Fixture preparation explicitly selected
the already tested 7.0 kernel outside the installer; this does not bypass the
Ubuntu VGA compatibility refusal.

After successful removal, malformed generated test-footer syntax prevented the
last health probe and shutdown. A separate corrected job independently rechecked
package restoration, boot choice, absence of nDPI and kernel health before
shutting down the VM. The failed footer receipt is retained.

Machine-readable hashes and bounded results are in VALIDATION_EVIDENCE.json.

## Post-rc1 safety review

Review reproduced package ownership contamination: an administrator's later
package could enter the global before/after difference and removal plan. Private
dpkg logs now attribute new installed packages to one operation UUID. An incomplete
receipt stops lifecycle sealing. Disable retains the previously owned scope;
sysctl writes require matching worker receipts. Existing APT manual/auto marks
are preserved, and interrupted disable resumes until restoration is complete.

APT --no-upgrade was independently shown to allow dependency upgrades. An
invocation-scoped Pre-Install-Pkgs hook now refuses replacement, reinstall or
architecture changes of any already installed package before dpkg executes.
The direct dpkg path also checks archives. CLI package timeout is propagated
to the controller as TimeoutExpired, leaving recovery to systemd after it has
stopped the worker control group.

A delayed recovery timer was reproduced stopping a newer tuning worker and
deleting its pending marker. Recovery now checks the exact transaction under a
state lock, cancels only its own timer and conditionally clears its own pending
record. Symlinks and foreign recovery units are refused before writes; rollback
checks saved file ownership as well as content and mode.

These changes do not establish production acceptance. Concurrent administrator
writes to the same managed file during installation do not yet have complete
per-writer provenance; drift between operations is refused before mutation.
Old lifecycle journals without package provenance are refused, not silently
adopted. The one-command production bootstrap remains disabled.


## Isolated rc2 integration acceptance

The updated exact code hashes are recorded in REVIEW2_VALIDATION.json. On the
isolated Ubuntu 24.04 / custom XanMod 7.0 fixture, actual APT and dpkg installs
produced separate ownership receipts. A later administrator package survived
repeat installation, disable and removal. Both direct replacement and an
indirect dependency upgrade from a private local package repository were
refused by the real APT hook before dpkg changed the installed version.

Intentional health exit 17 restored the network profile. A delayed recovery
from that completed transaction left a newer worker PID and pending record
unchanged; the new worker completed successfully. A 120-second health timeout
triggered systemd OnFailure recovery, restoring all 15 measured sysctls and
cancelling the matching fallback timer. The first probe lacked conntrack in
the empty fixture and stopped before mutation; it is retained separately.
An initial identity probe used the wrong copy/readiness time ordering; its
failure is retained alongside a corrected check of the actual package-suite
copy interval, guest manifest, unchanged code hashes and exact receipt hashes.

Fresh full installation, repeat installation, disable, repeated disable,
verified resume and removal also passed on that fixture. Three local payload
rounds checked DNS policy, nDPI matching and Suricata blocking. The immutable
baseline, original packages/sysctls and boot choice were preserved. Removal
reported that the loaded livepatch still required a reboot; a separate new
boot confirmed its absence and no managed firewall hooks or kernel faults.

The updated kernel-only path also prepared custom XanMod 7.2 alongside the
running custom 7.0 kernel. Two exact kernel packages were attributed, no guard
was installed, the saved boot entry stayed unchanged and status returned 20.
Removal restored the original package set. This tests preparation and removal;
runtime module acceptance on 7.2 remains the separately versioned rc1 evidence.

This is bounded local acceptance, not production or load acceptance. The
production bootstrap stays disabled pending fresh server checks and review
of remaining limitations.
