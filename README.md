# Patch Semaphore

Release trains need a red signal that cannot be waved through by the same person who shipped the code.

Patch Semaphore freezes a release policy and lockfile, then asks GenLayer validators to inspect a live public advisory against that exact baseline. A safe release clears immediately. An affected release enters a timed quarantine. Only the maintainer can submit patch evidence, and a separately named reviewer must approve the verified remediation before the signal turns green.

## Operating rule

`REGISTERED → CLEARED`

or

`REGISTERED → QUARANTINED → AWAITING_REVIEW → CLEARED`

An unresolved quarantine becomes `EXPIRED` through a permissionless call after its deadline. Failed patch attempts remain countable and can be retried before expiry.

## Evidence bindings

- The policy and initial manifest are fetched, bounded, stored, and hash-pinned at registration.
- Policy, manifest, and advisory must use three different HTTPS origins.
- Every advisory decision binds the exact response digest, affected component, and severity.
- Patch manifest and remediation report must come from separate new origins.
- Validators refetch every live source and recompute every state-driving field.

The included web records are operator-controlled demonstration fixtures. They prove reproducibility of the workflow, not independence of real-world publishers.

## Verification

```text
python -X utf8 -m genvm_linter.cli contracts/contract.py
python -m pytest -q tests/test_surface.py -p no:cacheprovider
gltest tests/direct -v
```

## StudioNet coordinates

- Contract: `0x38FF51c53b0063513297c355c84Be228E30FfB8f`
- Deployment transaction: `0xc397d86d387629ad6883cebd7ed96eec398a729aecb4346695416b71f72c0383`
- Verified release: `PS-LIVE-1790461068` (`CLEARED` after four finalized transactions)
- Public signal cabin: https://samiinw-patch-semaphore.pages.dev/

The deployed source is the contract at commit `84e3f3644ca1c46750a8bf76f994bf64dafc8fe1`.
