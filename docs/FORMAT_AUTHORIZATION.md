# Android password authorization before formatting userdata

This change governs the recovery's Format Data and Android reset backend. It does
not perform a physical format as a test. Reusable authentication is limited to
the exact qualified Evolution 16 password profile. Other supported profiles keep
their existing legacy lifecycle; see [Reusable CE sessions](reusable-ce-session.md).

## User flow and public interface

1. Choose the intended Format Data operation in the current recovery session.
2. If data is locked, use the existing read-only Android preparation to discover
   the stored credential type. A verified reusable mounted or suspended session
   can proceed without creating another native runtime.
3. Send the current password/PIN through the existing anonymous native credential
   FD to `filesystem.py format-authorize`. This always requests fresh native
   verification. For a reusable session, any current mount is normally suspended
   before the credential is consumed, then the existing CE data is opened
   read-only. This step does not erase data.
4. Present a separate explicit hold-to-erase confirmation. The final operation
   validates the grant and the same live authentication and mount epochs,
   terminally closes the session, proves cleanup, spends the grant and then
   invokes the formatter.

An ordinary existing decrypted mount or cached CE key does not prove a newly
entered password. Qualified reusable mounted and `session_unmounted` sessions
can verify the current password again without rebooting, under every password
policy. A suspended session cancelled before its first authentication is also
eligible for a fresh verification; its empty cache cannot authorize formatting.

Profiles retaining the legacy one-shot lifecycle still require a fresh recovery
boot when their mount or consumed attempt prevents another authentication. The
interface must explain that requirement before opening a password prompt.
Terminally closing a TEE runtime also retains the existing new-boot requirement
before reinitialization.

```text
filesystem.py --device format-authorize
  --volume userdata --fs ext4|f2fs --purpose format|android-reset
  --expected-volume-token CURRENT_VOLUME_TOKEN
  --credential-fd FD --android-user 0

filesystem.py --device format
  --volume userdata --fs ext4|f2fs
  --expected-volume-token RAW_PHYSICAL_VOLUME_TOKEN
  --format-authorization GRANT --confirm

samsung_firmware.py --device reset-data
  --format-authorization GRANT --confirm

filesystem.py --device format-cancel --format-authorization GRANT
```

`CURRENT_VOLUME_TOKEN` is the verified prepared, mounted, or suspended token for
the current session. Final formatting uses the separate raw physical token
returned by authorization.

The anonymous FD carries the credential directly to the existing native path.
Python does not read, log, save or put the password in argv. The authorization
module has no authenticate-only replacement or local password comparison.

The successful authorization response includes:

- `volume`: the actual current mounted RO volume and session token.
- `format_authorization`: an opaque 64-hex-character grant.
- `format_volume_token`: the raw physical userdata token for final format.
- `format_purpose`, `format_fs`, `expires_in_seconds: 120`.
- `authentication_performed: true`, `authentication_run_id`.
- For reusable sessions: `session_reusable: true`, a fresh `authentication_id`,
  and positive `auth_generation` and `mount_generation`.
- `ce_authenticated: true`, `fscrypt_policy_verified: true`.

Inventory adds `format_auth_state` and `format_auth_reason`. States are
`not_required`, `required`, `restart_required`, and `unavailable`. They guide
the UI; they cannot authorize a formatter. Qualified reusable mounted and
suspended sessions report `required`: another current password verification is
needed, even if a cached ordinary mount would be allowed. Legacy mounted sessions
and states requiring a new boot retain `restart_required`.

A separately held grant must still satisfy its own expiry and exact session
bindings. A later authentication or mount/suspend transition changes the bound
identity or generations and invalidates the earlier grant.

## Binding, cleanup and replay

The root-owned 0600 grant resides in a root-owned 0700 RAM directory. It binds the
boot UUID, internal eMMC identity and partition geometry, raw volume token,
filesystem identity, native run/profile/user/credential type, supervisor and
worker PID/start times, mount/device/mode, public CE policy digest, intended
operation, target filesystem and a monotonic 120-second expiry. Reusable grants
also bind `authentication_id`, `auth_generation`, and `mount_generation`.
Before issue, the module requires a fresh native result and independently checks
the live session against the verified baseline run and physical volume. When
there was an earlier accepted authentication, the new ID must differ and
`auth_generation` must advance. A never-authenticated suspended baseline has
`auth_generation=0`, a null ID, and no retained key. The result, public volume,
and live session must agree on the new authentication and mount epochs.
No caller-supplied authentication boolean is accepted.

Before terminal closure, an exclusive RAM attempt marker blocks concurrent or unknown
replays. A structured `VOLUME_BUSY` with `session_preserved: true` can release
that marker only after an independent comparison proves the live session,
volume and policy unchanged. The UI may then offer another explicit confirmation
within the original expiry. The backend never retries automatically.

Successful terminal cleanup must remove the public and private mounts, owned
crypto mappings and physical partition holders. For reusable sessions, it also
wipes the cached CE key and reaps the native key owner. The formatter requires
`close_session()` to return `session_closed=true`,
`session_retained=false`, and `cleanup_verified=true`. Ordinary unmount may
retain a reusable session and does not satisfy this gate. The grant is then
consumed immediately before the destructive writer.
A timeout, lost result, changed session, failed cleanup or failed formatter never
makes the token reusable. Cancellation revokes the grant and leaves a successfully
opened RO mount unchanged; the normal explicit Unmount action remains available.

## What is admitted and what is refused

The implemented password flow covers the qualified native password credential
type, including a PIN handled by that native path. Native NONE, pattern and
unknown/damaged metadata do not silently count as a verified password. Those
format authorizations remain unavailable in this implementation.

Existing positively identified unencrypted ext4/F2FS volumes retain their normal
explicit formatting path. An encryption-capable or unknown userdata requires
the Android authorization, unless this same boot has a verified post-erase fact
described below. Missing crypto metadata never becomes an erase fallback.

## Post-erase fact, separate from authentication

After a successful intended mkfs and a fresh filesystem probe, the backend may
record that it initialized userdata in this recovery boot. The new filesystem
type and nonempty UUID must match expectations, the UUID must differ from the
pre-write UUID, and physical identity must be unchanged. A failed formatter,
unchanged UUID, failed probe, failed or incomplete filesystem probe creates no
such receipt.

The existing Linux-to-stock installer preserves its current Linux backup checks
and refuses protected original userdata before any target write. Its stock image
write list excludes userdata; the guarded reset initializes userdata afterward.

The RAM receipt binds the new physical token/UUID, boot and operation provenance.
It is not password authentication, has no public creation command, and does not
authorize erasing old protected data. It permits completing a subsequent OS
installation after data has already been intentionally erased; otherwise a fresh
empty F2FS with encryption capability would incorrectly be treated as still
holding the old Android password. A changed boot, UUID, token or device invalidates
the fact, and an observed authenticated/prepared credential session takes priority.

## Audited write paths

| Entry point | Enforcement |
| --- | --- |
| Files `filesystem.DeviceContext.format` | Validate password grant before cleanup/mkfs for protected userdata; preserve normal card/cache handling. |
| Wipe `samsung_firmware.reset_data/android_data` | Validate before cache wipe or userdata unmount; pass exact grant to the raw reset backend; cache is cleared only after verified data reset. |
| Raw `install.DeviceContext.reset_android` | Independent gate before opening metadata or invoking either formatter. |
| Samsung firmware installation | Refuse protected original userdata before inspection/flash; user explicitly formats through Wipe first. |
| GSI installation | Same early refusal before image writes. |
| Linux-to-stock installer | Early original-data gate plus existing verified current Linux backup; the guarded final reset formats the still-unencrypted Linux userdata. |
| Distro clean install and damaged-settings userdata format | Reach the guarded `DeviceContext.format`; no alternate mkfs bypass. |
| Linux compact wipe | Existing independent current BOOT and userdata-against-Linux-backup verification occurs twice before its raw formatter; unchanged. |

Restoring a whole existing backup is a separate operation with its existing
admission rules. A recovery backend guard cannot prohibit arbitrary root shell
commands or external bootloader tools.

## Validation boundary

Focused tests use only owned temporary files and mocked native auth, sessions,
mounts and formatters. They cover wrong/missing credentials; old mounts; reusable
mounted and suspended baselines; a suspended baseline with no prior accepted
authentication; false fresh-auth flags; changed authentication IDs or generations;
wrong boot/run/volume/session/policy; expiry; purpose/filesystem mismatch;
cancellation; one-use consumption; known-busy and unknown terminal cleanup;
early no-write refusals; and post-erase identity/UUID/readback constraints.
Physical password authorization and destructive formatting are not claimed from
these synthetic checks.
