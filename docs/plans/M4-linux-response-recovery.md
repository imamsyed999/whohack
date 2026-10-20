# Linux response recovery acceptance

Close the missing-table recovery gap in `vigil-respond/src/linux.rs`: verify the
private nftables rule remains installed, and release idempotently after an
external table deletion. All changes remain scoped to the random Vigil table.

Add an ignored owned-process acceptance test that requires an explicitly isolated
network namespace. Verify new loopback connections stop, an unrelated process
continues, table deletion is detected, release restores connectivity and repeated
recovery succeeds. Keep PID migration's kernel API limitation documented.

Run the test as root in a new network namespace; do not change the host ruleset.
Run ordinary Linux response tests and strict Clippy after the change.

Execution: idempotent release and missing-table recovery passed in a fresh
network namespace, including original cgroup restoration. Full blocking could
not run because the WSL kernel disables CONFIG_NFT_SOCKET. Ordinary workspace
tests and strict Clippy pass. The kernel-specific block gate remains open.
