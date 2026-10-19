# Allocator repair candidate — not a production release

The previous `v1.7.11-dsg1` is withdrawn. Its short acceptance windows missed
delayed KFENCE reports in the upstream realloc callback. Historical observations
remain in HISTORICAL_DSG1_VALIDATION.md and do not approve this candidate.

The actual original callback reproducibly fails ASan when growing 2048 bytes to
4096 bytes. The patched callback passed 794 ASan/UBSan cases, including growth,
shrinkage, calloc overflow, allocation/metadata failures and metadata cleanup.
Fourteen compatibility, preservation and listener tests pass. The compatibility
gate now refuses activation after an existing kernel fault in the current boot.

Modules compile for all four listed kernel/OS pairs. The Ubuntu 22.04 build
uses an isolated official Ubuntu 22.04 container, GCC 12.3.0 and exact
6.8.0-87.88~22.04.1 headers. No production source tree is overwritten.

The native allocator harness passed 686 cases in an isolated Ubuntu 6.8.0-147
VM using the actual kernel krealloc/XArray/vmalloc implementation, including
atomic packet context and a vmalloc allocation larger than kmalloc's limit.
KFENCE sampling was set to 1 ms in the isolated VM only.

Completed isolated TLS traffic checks:
- Pending.

The corrected module has not been reaccepted on production. Existing production
nDPI packet matching remains held after the old allocator fault; independent
Suricata/DNS filtering was retained. No new ready-to-install release is approved.
Repeated installation, rollback, cold boot, longer observation and actual
application-path acceptance must be checked before that status changes.
