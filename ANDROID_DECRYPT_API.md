# Android password and pattern decryption in recovery

This integration exposes the qualified Samsung SM-A226B Android 13, POST_RESET03,
user 0 credential profile through Files, using the original Samsung Gatekeeper,
Keymaster and native secure-storage services.

## User flow and present limits

Files → internal userdata → Mount first prepares the current native protector
without a credential or Gatekeeper verification. Only after native validation does
the UI display either a masked password field or a 3×3 pattern grid. The type is
read from the current protector; user0 does not imply a particular credential type.

The grid follows the verified Samsung midpoint/duplicate rules. It requires 4–9
points and explicit Unlock; releasing a gesture does not authenticate. Clear
erases the entry. The secret stays in locked native memory and an anonymous pipe.
After successful normal authentication, F2FS remains mounted at
/mnt/volumes/userdata for later Files operations. Filesystem and block mapping
remain read-only.

Cancel wipes the entry and requests normal native cleanup. The prepared prompt has
a 300-second lifetime. Cancel, expiry or completed unmount requires a restart of
recovery before another session: the same boot cannot replay TEE bootstrap.
A busy normal unmount preserves an authenticated session. No forced/lazy unmount,
automatic credential retry or credential change is used.

The installed successor has physical evidence for two-phase preparation and normal
known-password CE authentication, an independent Files read after auth exit, and
clean normal unmount. Preparation/cancellation without a credential was also
physically checked on the matching backend. The real pattern profile, manual
touchscreen authentication and non-ASCII passwords still require separate physical
qualification: the current native protector is password4. The immutable image's
external receipts record these limits.
GSI14–16, other phones, secondary users, PIN type3, app installation and userdata
writes remain unqualified. Hardware-backed app secrets do not become portable by
opening the filesystem. The virtual keyboard does not cover every Unicode
character.

## Files API

Inventory Android fields include decrypt_supported, decrypt_state,
credential_required, preparation_required, credential_type, android_user_id,
decrypt_profile_id, retry_after_seconds and unlock_reason.

A fresh encrypted volume has credential_type=unknown and preparation_required=true.
Preparation accepts no credential:

    filesystem.py --device prepare-android --volume userdata
      --expected-volume-token PHYSICAL_TOKEN --android-user 0

Success returns {volume,credential_type,ce_authenticated:false}. The volume has
decrypt_state=awaiting_credential, verified credential_type=password|pattern,
preparation_required=false, mounted=false and ce_authenticated=false.
Its new volume_token binds schema/boot/run, supervisor and worker PID/starttime,
physical token, user/profile/type and the actual private native RO mount identity.
The original token is retained as physical_volume_token. This pending receipt
does not authorize Files access.

Explicit authentication uses the returned pending token:

    filesystem.py --device mount --volume userdata --mode ro
      --expected-volume-token PENDING_TOKEN --android-user 0 --credential-fd FD

FD is an anonymous pipe read end numbered 64–4096. Python transfers the FD with
SCM_RIGHTS and promotes received descriptors to >=64 without reading the payload.
There is no --credential-type option: the pending receipt supplies the verified
type, and the native decoder independently compares it with the current profile.

Native frames (little endian u32 fields):

| Frame | Prefix | Type | Length | Payload |
|---|---|---|---|---|
| Legacy v1 | none | password4 only | u32 byte count | strict UTF-8 password |
| Typed v2 | ASCII A22C | u32:1 or4 | u32 byte count | canonical ASCII1..9 pattern, or strict UTF-8 password |

The frame is sent once, maximum 256 payload bytes, with exact EOF and a 5s native
deadline. Pattern type1 requires canonical 4–9 distinct cells. Password type4 uses
the exact pinned Samsung framework conversion: Java UTF-16 units contribute the
high byte only if the unit exceeds 255, then the low byte. No Unicode normalization
is performed. Type mismatch and malformed input fail before Gatekeeper.
Credentials never belong in argv, environment, regular files or JSON. Native
UI/consumer code owns and wipes the memory.

Cancel uses the same pending token and supplies no secret:

    filesystem.py --device cancel-android-unlock --volume userdata
      --expected-volume-token PENDING_TOKEN --android-user 0

It returns ce_authenticated:false and reboot_required:true only after cleanup
proof. A stale token/process/source or expired prompt is refused.

A successful authenticated receipt exposes ce_authenticated,
fscrypt_policy_verified, decrypt_run_id and the mounted volume_token. Its boot/run/
mount/device binding is independent of the pending token. An exited worker or
replaced mount cannot authorize access. The previous direct one-shot password
helper route remains available for compatible callers.

Normal Files operations use PinnedVolume. Unmount is:

    filesystem.py --device unmount --volume userdata

GENERAL_FAILURE remains a decryption failure; it is not relabelled as a wrong
password. Native retry status retains its delay without automatic retries.

## Ownership and lifecycle

android_decrypt.py validates the pinned profile and descriptor.
decrypt_prepare.py verifies the runtime archive, restores exact archived modes,
bootstraps TEE once and makes a current-boot opaque EFS safety copy in cache.
Both exact services.jar and framework.jar hashes are checked before preparation
and again immediately before authentication.
The original EFS is mounted under the qualified native persistence policy so
legitimate Gatekeeper storage/counters can be updated. Userdata and metadata
remain read-only.

decrypt_session.py owns a supervisor. The worker authenticates, verifies the CE
key policy and transfers the F2FS mount through open_tree/move_mount. The transfer
descriptor is closed after attachment. Exact owned metadata identifies eight
required long-lived services; completed one-shot helpers are not health-checked.

The common operation lease is borrowed. Children do not issue LOCK_UN on the
shared open-file description. On preparation/authentication readiness their borrowed references are closed,
allowing later Files commands to acquire the lease. Authentication, cancellation
and unmount supply a fresh lease. A reserved worker FD number is replaced by the
fresh lease without issuing LOCK_UN on any borrowed description.

A held session retains service/watchdog monitoring. Success at terminal cleanup
requires normal unmount, reaping, no remaining owned mapping and a direct physical
EFS superblock check. Receipts contain no credential payload.

EFS safety copies consume 8 MiB per prepared boot. New managed-v1 snapshots retain
the two newest verified copies; unmanaged legacy copies are never automatically
pruned. Cache capacity/ownership checks run before TEE bootstrap, and preparation
requires 12 MiB free. Old EFS must never be restored to reset attempts or mix
credential epochs. See the retention details below.

## Packaging and validation

tools/build_decrypt_image.py accepts the exact qualified base and external pinned
runtime. It preserves kernel/DTB/DTBO/unlisted CPIO entries, emits checked-hash
CPython 3.14 bytecode and verifies AVB and the 40 MiB partition budget. Vendor runtime
contents are not added to this source tree.

Hardware-test metadata is pending at build time; external evidence qualifies the
immutable image. Updating that metadata would create a different image.

Previous installed image SHA256:
59e9f8dca27c84cb7a84e280f85133e10df59b67a06f3ac1dfa8135ef9545d87

Evidence on Arch:
 $HOME/a22x-work/artifacts/lk-recovery-bridge-20261114/stage-c/password-sp/permanent-integration-20261116/REPORT.uk.md

Previous image source tests: 100 Files + 12 adapter + 28 session = 140 PASS.
UI: native descriptor framing test and 106 self-tests, also ARM64 under QEMU.
Physical validation used the recorded-password native helper and installed Files
backend, then an independent read after auth exit and normal verified unmount.
It does not claim manual real-password entry through the physical touchscreen.


## Standard build entry

The normal build script can route explicitly to the qualified preservation builder.
In fish, after setting the actual verified input paths:

    set -x A22X_ANDROID_DECRYPT 1
    set -x A22X_ANDROID_DECRYPT_BASE_IMAGE /absolute/path/to/qualified/recovery.img
    set -x A22X_ANDROID_DECRYPT_RUNTIME_ARCHIVE /absolute/path/to/native-pattern-password-v3.tar
    set -x A22X_ANDROID_DECRYPT_WIFI_MODULES /absolute/path/to/matching/wifi-modules.tar.xz
    tools/build-image.sh 1001

The output is build-password-1001 below A22X_RECOVERY_WORK (the source parent by
default). An existing output directory is refused, never removed. Input hashes
and kernel preservation checks remain mandatory. PUBLIC=1 is refused for this
personal qualified base.

The legacy build path also packages adapter/session modules, preventing a
missing-module regression when Files imports the adapter. It does not silently
enable decryption on an older kernel or without the qualified vendor runtime.

## Pattern/password successor source

Public native converter/frame sources, synthetic tests and exact integration patch
are retained in runtime-source/samsung-a13-credential/. The proprietary runtime
archive remains external. Its SHA256 is
c7e1186df1eb057a9a25367013d13fc245a47a0ab1c2d12914cc6567780c6d79;
native executable b742f3bc00b870e856205019c721fd01259b7ffb17369c82cdf04bb4ac735f4d.
Source profile qualification counts describe build-time evidence, not a self-test.

Current successor evidence on Arch:
 $HOME/a22x-work/artifacts/lk-recovery-bridge-20261114/stage-c/password-sp/pattern-integration-20261116/

Do not confuse its live qualification with the previous installed image above.

## Installed pattern successor: physical qualification, 2026-11-16

Installed image SHA256:
08fec7a5073df9c0ccb1633b0b8bead837c9c0b2ed132c2a70e348ee2fd74b78

The native recovery update made and fully read back its rollback image, then fully
read back the target. BOOT remained unchanged. All 28 installed runtime/UI files
matched on fresh boot; no runtime RAM overlay was used for password authentication.

One recorded native-helper submission after successful preparation produced both
qualified Gatekeeper TA statuses 0/0, CE authentication and fscrypt policy match.
An independent operation lease read 14 media/0 entries after the auth command
exited. Normal unmount reaped all owned processes and left no DM/block mount/open
watchdog FD; direct physical EFS was clean with no error or recovery flag.

The preparation/cancel trial made zero command126 calls and performed normal
cleanup. Its 14 non-PYC runtime files match the image byte for byte; 12 checked-hash
PYC files have equal headers and recursively equal code fields, including filenames,
while their marshal serialization bytes differ. See RUNTIME-PROVENANCE.json.

Final fresh boot 42ebc4c8-9f4d-4b4d-9f47-c47599a2e800 has the installed UI running,
all 28 pins matched, no test password helper, no active mounts/DM/watchdog FD, and
no new authentication. The phone remains ready for owner interaction.

The pattern grid is installed; a real pattern CE unlock is NOT_TESTED because the
current protector is password4. The owner must set their own pattern normally in
Android and enter it directly in recovery for that qualification. No lock credential
was changed by this integration. Manual physical password entry and Unicode password
hardware cases are also unqualified. Existing source profile counters remain
build-time metadata; these receipts qualify the immutable image externally.

Final tests: 157 source tests (100 Files, 12 adapter, 28 session, 16 discovery,
1 cross-layer profile pin), 106 UI self-tests plus native FD/gesture/lifecycle
checks, native codec 86/frame 140/resolver 9 checks with sanitizer and ARM64 builds.
Details, failed intermediate harness logs and exact qualification limits:
 $HOME/a22x-work/artifacts/lk-recovery-bridge-20261114/stage-c/password-sp/pattern-integration-20261116/REPORT.uk.md


## Cache admission and EFS snapshot retention

Preparation first mounts cache read-only through the existing Files volume helper,
checks its admitted ownership/mount identity and at least 12 MiB available space,
then normally unmounts it. A capacity failure happens before the run directory,
runtime extraction or TEE bootstrap is consumed. Its safe current-boot reason stays
visible in inventory; after freeing space it can be retried without reboot.

New EFS snapshots live under `a22x-recovery/private-efs/managed-v1/`. A separate
root-owned `retention-v1.json` ledger binds exact canonical boot UUID filenames,
image SHA-256 and persisted receipt SHA-256. After a new image is fsynced and fully
reread and its receipt/ledger are durable, only the oldest verified managed pair
may be removed, keeping the newest two. The current boot is never retired. Legacy
files outside this directory are never adopted or pruned. The schema1 native EFS
receipt remains unchanged; its backup_relative now identifies the nested image.

A malformed ledger, unexpected file/owner/mode/link, changed hash or interrupted
commit/prune stops retention with no guessed cleanup. A durable pending prune
currently requires manual review; it is not automatically resumed. No snapshot is
automatically restored and no credential/counter state is changed by retention.

If a failed preparation already dispatched bootstrap, current-boot markers and
observed TEE gates make inventory return `decrypt_state=reboot_required` even
without a session.json. A valid live prepared/authenticated session still takes
precedence. An earlier cache-space reason is retained when available.

## Kernel module packaging invariant

The preservation builder verifies the actual preserved kernel release and every
bundled ELF AArch64 module vermagic, including SPM and all four Wi-Fi modules.
An inherited incompatible Wi-Fi archive is rejected before compression. Supply
--wifi-modules to the direct builder, or A22X_ANDROID_DECRYPT_WIFI_MODULES to the
standard shell entry. The archive must be XZ because the runtime uses tar -xJf.
Kernel/module/archive identities are recorded in build.json and RESULT.json.

The bundled Beaver theme is no longer built or added by the standard image entry.
Its source remains available as a test fixture; this does not affect distro entries.

## Installed Wi-Fi/cache repair and Beaver removal, 2026-11-16

1.1.0-dev-fix1 (79738fee540cc07a201c6227bd72038f6dcd1f589e2d83341dd4f77ef390ee9b)
was installed with native backup/full readback and a fresh boot. The exact #145
Wi-Fi modules passed cold-boot auto-connect and scan. One recorded known-password
submission yielded qualified Gatekeeper TA statuses 0/0, CE policy match, an
independent Files read, normal unmount and direct clean EFS. The managed backup
ledger/image/receipt were independently re-read; cache retained one snapshot.

1.1.0-dev-fix2 (66c3f3c182d03184002fd2f78c2f5ca8b2da3260e4abf17e137ca7115273a867)
then removed only the pinned Beaver theme and changed build metadata. An independent
CPIO comparison proved all other entry bytes/metadata, UI, decrypt runtime and
kernel/DTB/DTBO unchanged. Native backup/full readback and another fresh boot
verified all29 runtime pins, running UI, automatic Wi-Fi, and no bundled or
imported Beaver theme. No unnecessary second password submission was made for
the asset-only change. Final boot b31711fd-6eaa-4faf-b836-f83612198a32 is fresh,
with TEE gates -11 and the recorded test helper absent.

The removal recovered 71680 partition payload bytes (70 KiB); the raw theme was
2042511 bytes but highly XZ-compressible. The final 40 MiB image has 256000 bytes
after aligned payload, including AVB space. Above the builder's mandatory
131072-byte reserve, 124928 bytes remain. RAM overlay metadata marks the tar
as incomplete for deletions; use the full qualified image or explicitly process
REMOVED.json with equivalent ownership checks.

Current evidence on Arch:
 $HOME/a22x-work/artifacts/lk-recovery-bridge-20261114/stage-c/password-sp/modules-installer-20261116/REPORT.uk.md

Final source verification:66 tests,0 failures/errors/skips. Userdata remains RO.
Actual pattern authentication, GSI14-16 and durable root-module/userdata writes
are still unqualified. The previous native goal remains blocked and was not edited.
