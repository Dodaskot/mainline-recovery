"""Source/target build pairs that completed hardware qualification: a system update that keeps
Android's data (android_gsi.py --keep-data) is offered only for one of them.

A pair: the SHA-256 of what super/system held before (lp_metadata read_partition, as this
recovery's installer wrote it) and the SHA-256 of the file installed over it, with what was checked
on the phone after its first start. Only BOOT's root, vendor, userdata and the rest of super stay as
they were; the return to the earlier system is the partitions copy the update makes first.
"""

VANILLA = {'name': 'crDroid 12.12 (Doze-off Treble GSI 2026-09-22) without Google apps',
           'system_sha256': '5595851f2f6a1f341000d085276bbe28ca584f25ab04236270ece828c27005d0',
           'package_sha256': 'b0797c0c93b7fbfbae4cec0e7440fd6f0527abbbc891cc57ac186445d5ef5871', 'package_bytes': 974151100}
MICROG = {'name': 'crDroid 12.12 (Doze-off Treble GSI 2026-09-22) with microG',
          'system_sha256': '79a6a0d8c1a092534682558594e55045fc37752a9c114d87325564dfd7b8f2cb',
          'package_sha256': '1afddd51b6f457f02046cdd0e15abd7d5bd5480a789ac3fb0aa05da040ecf076', 'package_bytes': 1061804316}


# What else an update that keeps the data runs on (2026-11-22, the owner: a pair is qualified on a BOOT
# and its kernel, a vendor, verification and encryption, not by its files alone). android_gsi
# platform_facts reads the same keys from the phone; a pair is offered only on a platform it was
# checked on, and the differences are named otherwise.
PLATFORM_KEYS = ('kernel', 'root', 'vendor_sha256', 'vbmeta_flags', 'data_encrypted')
# LineageOS 20's vendor in super (1 093 529 600 bytes; a GSI installation writes only super/system),
# verification off (flags 3: hashtree and verification disabled), its fstab asks for no encryption.
LINEAGE20_VENDOR = '99a3e0ffe51745a0a5003fd4db6f1bf30e8e233bc16e183123f4219933d706bd'
SAMSUNG_MAGISK = {'kernel': '4.14.186-27218697', 'root': 'magisk', 'vendor_sha256': LINEAGE20_VENDOR,
                  'vbmeta_flags': 3, 'data_encrypted': False}
# 2026-11-22, recovery 1.1.0-dev-device-feedback.138, KernelSU Next's BOOT (6ec45c06, 4.14.186+), the
# same vendor and vbmeta: vanilla (data migrated from LineageOS 20: two apps, a contact, Wi-Fi, settings,
# shared files) -> microG with --keep-data --qualification-run, first start 86 s, microG's GmsCore there,
# both apps with their uids and categories, root over adb, no crash; then microG -> vanilla the same
# way, first start 81 s, the same data, microG gone with its system.
KERNELSU_NEXT = {'kernel': '4.14.186+', 'root': 'kernelsu', 'vendor_sha256': LINEAGE20_VENDOR,
                 'vbmeta_flags': 3, 'data_encrypted': False}


def _pair(source, target, evidence, platforms):
    return {'source': source['name'], 'source_manifest_sha256': source['system_sha256'],
            'source_package_sha256': source['package_sha256'], 'source_package_bytes': source['package_bytes'],
            'target': target['name'], 'target_package_sha256': target['package_sha256'],
            'target_package_bytes': target['package_bytes'], 'evidence': evidence, 'platforms': list(platforms)}


# 2026-11-21, SM-A226B, recovery 1.1.0-dev-device-feedback.97, kernel #155, Samsung BOOT with Magisk
# 31.1, LineageOS 20's vendor (data without FBE), userdata with an app and its data, a contact and
# shared files carried over from LineageOS 20:
# - vanilla -> microG with android_gsi --keep-data (the way back, vanilla's own image, checked
#   first): first start in 95 s; the app (1.8, its data owned by u0_a347), the contact, Magisk's
#   root over adb, the Magisk app and the shared files there; microG GmsCore 0.3.16.252432 added;
#   no new crash (only the vendor's fingerprint HAL, as before).
# - microG -> vanilla from Files (Flash to a partition, super/system; read back byte for byte):
#   first start in 91 s with the same data; microG's packages gone with its system.
QUALIFIED_TRANSITIONS = (
    _pair(VANILLA, MICROG, 'live 2026-11-21: update keeping the data, first start, data and root checked', [SAMSUNG_MAGISK, KERNELSU_NEXT]),
    _pair(MICROG, VANILLA, 'live 2026-11-21: the return from microG, first start, data and root checked', [SAMSUNG_MAGISK, KERNELSU_NEXT]),
)


def lookup(source_digest, target_digest):
    return next((entry for entry in QUALIFIED_TRANSITIONS
                 if entry.get('source_manifest_sha256') == source_digest and entry.get('target_package_sha256') == target_digest), None)


def targets():
    """(size, sha256) of every qualified target: only a file of one of these sizes is hashed for it."""
    return {(entry.get('target_package_bytes'), entry.get('target_package_sha256')) for entry in QUALIFIED_TRANSITIONS}


def offered(size):
    """Whether a file of SIZE bytes may be the target of a qualified pair (cheap: no hash)."""
    return any(entry.get('target_package_bytes') == size for entry in QUALIFIED_TRANSITIONS)


def platform_differences(pair, platform):
    """[] when PLATFORM is one the pair was checked on; else the keys that differ from the nearest one."""
    best = None
    for known in pair.get('platforms') or ():
        differ = [key for key in PLATFORM_KEYS if known.get(key) != platform.get(key)]
        if not differ:
            return []
        if best is None or len(differ) < len(best):
            best = differ
    return best if best is not None else list(PLATFORM_KEYS)
