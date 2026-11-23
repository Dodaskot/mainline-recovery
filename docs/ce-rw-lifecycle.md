> Historical ui1 lifecycle: the reboot limitation below describes the previously
> installed one-shot runtime. The new qualified-capability implementation is
> documented in [reusable-ce-session.md](reusable-ce-session.md); physical image
> qualification is recorded separately.

# Android CE access modes and lifecycle

This build enables persistent CE write access for the exact
`evolutionx-a226b-a16` profile with a password credential. The native helper,
kernel and quota-module pins are unchanged. Samsung Android 13, other GSIs,
patterns and the NONE credential do not inherit this write qualification.

The qualification evidence is the three-phase hardware cycle from
2026-11-16: write and fsync a 4 MiB marker; read the same complete hash after
a new boot and delete/fsync; verify absence in a new user-mounted production
RO session. Final receipt SHA-256:
`5d630cfc60dc6c4c3bc1c308d10718fec1c355821a9cb440278c0b70ae10c637`.
An image built from this source still needs its own installation and UI smoke
check; the source flag does not claim those checks have already occurred.

## Inventory contract

- Locked: `access_modes` lists provisional user requests. When the installed
  Evolution write capability is available, RO and RW may be selected before
  discovery. `access_mode_qualification=pending` and
  `decrypt_write_supported=false` explicitly mean that no RW admission has
  happened.
- Prepared: `access_modes` is narrowed using the live prepared receipt and
  qualified credential scope. Only exact Evolution/password exposes RW.
  The UI must check these fields again before submitting the credential.
- Mounted: `access_modes` contains the current mode only.
  `current_access_mode` and `read_only` report the verified actual mount.
  `available_access_modes` describes choices for a fresh session.
  `mode_change_requires_reboot=true` explains the fixed session mode.
- Closed, stale or failed: no mount modes are advertised and
  `reboot_required=true`; an advisory file never authorizes a new session.

RO-to-RW remount is not silently attempted. The native secure-world lifecycle
is qualified once per boot. Changing modes requires normal unmount followed
by a fresh recovery boot and a new normal authentication.

## Result handling

A same-mode mount or prepare on already-open data succeeds idempotently with
`already_mounted=true` and `authentication_performed=false`. A supplied
credential pipe is not consumed or verified in this path. This result must
never authorize formatting.

A newly completed prepared authentication returns
`authentication_performed=true` and `authentication_run_id` only after
checking the live authenticated receipt and independently observing the
requested mount mode. The format-authorization workflow must additionally
bind this result to its own explicit fresh intent.

`DECRYPT_MODE_FIXED` preserves the session and provides
`current_mode`, `requested_mode`, `reboot_required=true` and
`session_preserved=true`.

`VOLUME_BUSY` from a normal unmount preserves the live session:
close users of the mount and retry the unmount. Its result has
`retry_allowed=true` and `reboot_required=false`.

`DECRYPT_OUTCOME_UNKNOWN` denotes lost IPC during authentication,
cancellation or unmount. Refresh inventory to observe the actual state;
do not automatically send the operation again. The details include
`operation`, `refresh_required=true` and `retry_allowed=false`.

Credentials remain on the existing anonymous native FD channel. Python
never reads or logs the password. No TEE verification, cleanup, mount identity,
quota ownership or one-shot safety guard was relaxed.
