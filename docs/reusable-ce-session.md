# Reusable Evolution 16 CE sessions

This implementation is limited to the exact qualified Evolution 16 password
profile. Samsung and passwordless legacy sessions retain their existing
lifecycle. Initial UI capability is provisional until discovery identifies the
actual profile and credential; a discovered legacy session explicitly removes
the reusable capability flag.

## Password policy

The persisted setting `android_password_policy` has exactly three values:
`each_mount`, `startup`, and `first_access`. An absent, invalid, or unavailable
setting means `each_mount`. The UI owns startup timing. The backend enforces
whether a credential is required, including direct command-line requests.

Every actual mount in `each_mount` uses a fresh native password verification.
The two other policies may reuse a previously accepted CE key in the same
recovery boot. The key is held only by the hardened native owner, in locked,
non-dumpable anonymous memory; neither Python nor the settings store receives
password or key bytes. A current policy different from the policy used for the accepted authentication
requires another password. Returning to that same policy without an intervening
mount may reuse the existing valid boot-local cache.

A duplicate request for an already mounted volume does not constitute a new
mount and never claims new authentication. Formatting always forces a fresh
password verification regardless of the policy or cache.

## Startup prompt and initial credential window

When recovery starts with `startup`, the UI claims the startup attempt once
per boot when it can begin from the unlocked home screen. It requests RO access and uses the
normal preparation and password prompt. After its own successful mount result,
the UI verifies the RO mount and performs an ordinary unmount, leaving the
accepted key in the retained session for later mounts.

The RAM marker `/run/a22x-recovery/android-startup-prompted` is created before
inventory or preparation starts. It records only that the startup attempt was
claimed; it proves neither a displayed prompt, a successful prepared session,
nor authentication. Cancellation, an error, or a UI restart does not automatically
repeat that startup attempt in the same boot. State qualification requires the
actual live session and Files receipts.

The initial prepared session has a 300-second credential window starting when
native preparation publishes the prepared receipt. The marker does not extend
that deadline. On ordinary expiry, the reusable path suspends the private
prepared filesystem and preserves the unauthenticated native owner with no
cached key. This is a retained `session_unmounted` state, not successful
authentication or terminal closure. Uncertain cleanup still follows the existing
watchdog rules. Leaving or cancelling the password prompt also uses the normal
cancellation path; a recovery lock or access-request overlay can trigger that
cancellation before the credential deadline.

An external helper can authenticate the actual UI-created prepared session
through the normal Files API. Its successful RO receipt does not prove physical
UI submission or the UI's automatic unmount: that UI transition consumes its own
mount job result. Helper-based qualification must record its separate explicit
unmount and must not label the initial RO evidence as RW.

## What unmount means

Ordinary unmount first removes the public Files mount using normal unmount.
An `EBUSY` failure at this point preserves the original live session and its
mode. No native password or private cleanup is dispatched in that case.

The native owner then flushes and unmounts the private userdata filesystem and
removes all its owned default-key and raw aliases. Its root file descriptors
are closed. The supervisor independently verifies absence of the private and
public mounts, absence of the owned crypto mappings, and every visible mount
namespace's current backing graph. A reused DM minor is accepted only when its
current, stable name/UUID/dependencies resolve to unrelated physical storage;
unknown, cyclic, changing, or userdata-backed graphs are rejected.

The resulting `session_unmounted` state is a real filesystem unmount. Android
services, TEE context, the native key owner, and the original G1 read-only source
alias remain alive. Consequently `device_offline=false`: this state does not
authorize formatting or raw partition writes.

Remount creates a fresh filesystem and owned crypto mappings, restores DE/CE
through native code, checks the fscrypt policy and actual access mode, and
publishes a new mount only after an independent media read. RW uses the
qualified preflight, quota, health, and mode-transition checks.

## Terminal closure

`android_decrypt.close_session(context, volume)` is distinct from ordinary
unmount. It works for a mounted, prepared, or suspended session and requires:

1. Normal public/private filesystem removal.
2. Native CE key wiping and owner process exit.
3. Original Android/TEE service shutdown and EFS persistence checks.
4. Independent all-owned-process, mapping, mount, and watchdog cleanup proof.

Only this path returns `session_closed=true` and `cleanup_verified=true`.
Filesystem `unmount_all` uses terminal closure even when userdata was already
suspended. Format, flash, and reboot callers must use terminal closure and
their existing independent partition guards. A fully closed TEE runtime still
requires a new recovery boot before reinitialization.

## API and identity

Mounted and suspended public records include `session_reusable=true`,
`session_retained=true`, `android_password_policy`, and the typed Boolean
`mount_requires_credential`. Suspended state has `ce_authenticated=false`,
`fscrypt_policy_verified=false`, and `filesystem_unmounted=true`.

The native key owner has a bound PID/start time. Every mutation has a strict
request sequence and expected generation. A fresh accepted authentication has
a unique 32-digit hexadecimal `authentication_id` and positive
`auth_generation`; `mount_generation` changes across suspension, remount, and
other native transitions. A freshly prepared session starts with all native,
authentication, and mount epochs at zero. A never-authenticated session retains
`auth_generation=0`, a null authentication ID/policy, and no cached key, even
though cancellation or expiry can advance its native and mount epochs through
suspension. A failed later authentication preserves historical identity but
invalidates the key cache.

`android_decrypt.mount(..., require_fresh_authentication=True)` refuses cached
authorization, normally suspends any current mount before consuming the
credential, and returns the new native authentication identity. Format grants
must bind the authentication ID and both generations, in addition to their
physical-volume, boot, profile, process, and purpose bindings.

Cancellation at the first password prompt suspends the private prepared
filesystem and preserves an empty native owner. Cancellation of a later
password prompt does not dispatch authentication and preserves the observed
mounted or suspended session.

## Failures and diagnostic continuity

Every native operation uses a fresh verified operation lease. Idle processes
retain no copy of that lease. Secure calls have bounded deadlines; idle
mounted or suspended sessions remain live through verified heartbeats rather
than a boot-long authentication deadline. This does not extend the separate
300-second window for the initial `awaiting_credential` state.

A successful fresh authentication requires exactly two new qualified native
Gatekeeper TA-success records in that operation's diagnostic epoch. Cached
remount, suspend, close, and idle heartbeats require zero new verification
records. The streaming observer is pinned separately; per-epoch parser bounds
remain in force. Only complete validated epochs can rotate, preserving the
actually observed initial READY state, monotonic counters, a cumulative audit
digest, and a bounded recent record list.

Gatekeeper ERROR alone does not distinguish an incorrect password from another
verification error. The implementation preserves this limitation. A qualified
retry timeout remains a retry timeout. Known failures can leave a verified
suspended session with an invalid key cache; unknown secure outcomes,
incomplete cleanup, a lost owner, or mismatched generations never authorize
automatic replay. The existing watchdog handles uncertain secure state.

Host tests and code review are not physical qualification. Hardware receipts
for the final installed image are maintained separately by the sole phone
controller.

The completed image05/session4 hardware matrix is recorded in the
[17 November 2026 hardware report (Ukrainian)](reusable-ce-session-20261117.uk.md).
Its scope is the exact qualified Evo16 password/user0 profile; physical formatting
and physical UI credential submission remain outside that report's claims.

An interruption during initial secure-world bootstrap remains subject to the
existing watchdog and terminal cleanup rules. It is not treated as a completed
reusable session, and a restart can still be necessary after that interruption.
