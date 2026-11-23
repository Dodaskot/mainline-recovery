# Samsung Android 13 credential conversion

These are the exact public native sources used by the pattern/password successor.
They contain no user credentials, vendor firmware, device handles or keys.
native-integration.patch applies to the two pinned qualified input files in
SOURCE-PINS.json. The remaining native Gatekeeper/Keymaster/crypto objects are
unchanged. The external runtime and source build remain separately hash-pinned.

The input is UTF-8 for password type4 or canonical ASCII1..9 for pattern type1.
Samsung framework.jar731db55a… defines the password UTF-16 unit conversion and
pattern byte encoding; generic AOSP conversion must not replace it.
credential_frame supports legacy password-only framing and typed A22C framing.
The actual stored type is matched before secret payload processing.

The tests use synthetic inputs only. Host support requires the original
crypto/no-upgrade headers and Secret implementation. The exact qualified
Android link recipe, dependency hashes, optimized/sanitizer results and public
framework extraction are recorded on the Arch host at:

$HOME/a22x-work/artifacts/lk-recovery-bridge-20261114/stage-c/password-sp/pattern-integration-20261116/native/

Do not reuse stale .pwd/handle/SID data or use test sequences for live attempts.
Successful source tests do not establish physical pattern authentication.
