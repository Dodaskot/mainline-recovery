"""Qualified, boot-local reusable CE session policy and public identity checks.

Only the enum is persisted. The native owner keeps CE keys in locked RAM;
this module never reads a password or a key.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import threading

from android_profiles import EVO_PROFILE
from decrypt_runtime.common import require, same_process, boot_id as current_boot

SCHEMA = 'a22x.ce-session.capability.v1'
HELPER = '/system/bin/a22x-data-ce-session'
RAM_SNAPSHOT_HELPER = '/opt/a22x-recovery/a22x-data-ce-snapshot'
POLICIES = ('each_mount', 'startup', 'first_access')
IDENTITY_FIELDS = (
    'session_reusable', 'native_owner_pid', 'native_owner_starttime',
    'native_generation', 'native_sequence', 'auth_generation',
    'mount_generation', 'authentication_id', 'password_policy_at_auth',
    'key_retained',
)


def public_mount_failure(value):
    """Accept only bounded result fields from the native mount response."""
    if type(value) is not dict or set(value) != {'phase', 'errno', 'auth_dispatched', 'gatekeeper_verified'}:
        return None
    if (type(value['phase']) is not int or not 1 <= value['phase'] <= 14
            or type(value['errno']) is not int or not 1 <= value['errno'] <= 4095
            or type(value['auth_dispatched']) is not bool
            or type(value['gatekeeper_verified']) is not int or not 0 <= value['gatekeeper_verified'] <= 2
            or (value['gatekeeper_verified'] and not value['auth_dispatched'])):
        return None
    return dict(value)


_POLICY_READ = threading.local()

def password_policy(*, ram_only=False):
    # Inventory is used while settings loads its persistent record and migrates
    # themes. It must never recursively start another settings disk discovery.
    # Only an explicit policy enforcement read may initiate the first load.
    if getattr(_POLICY_READ, 'active', False):
        return 'each_mount'
    _POLICY_READ.active = True
    try:
        from filesystem import FilesystemError
        try:
            import settings
            if ram_only:
                record = settings.checked(json.loads(settings.RAM_COPY.read_text()))
                value = settings.android_password_policy(record)
            else:
                value = settings.android_password_policy()
        except (ImportError, AttributeError, OSError, ValueError, RuntimeError,
                KeyError, TypeError, FilesystemError):
            return 'each_mount'
        return value if type(value) is str and value in POLICIES else 'each_mount'
    finally:
        _POLICY_READ.active = False


def capability(value):
    require(type(value) is dict and value.get('schema') == SCHEMA
            and value.get('qualified') is True
            and value.get('helper') == HELPER
            and type(value.get('protocol')) is int and value['protocol'] == 1
            and type(value.get('helper_sha256')) is str
            and re.fullmatch(r'[0-9a-f]{64}', value['helper_sha256']) is not None,
            'UNSUPPORTED_PROFILE', 'Reusable native CE session is not qualified')
    if 'ram_snapshot_sha256' in value:
        digest = value['ram_snapshot_sha256']
        require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest) is not None,
                'UNSUPPORTED_PROFILE', 'RAM snapshot helper pin is invalid')
    return value

def available(profile):
    try:
        capability(profile.get('ce_session'))
        return profile.get('profile_id') == EVO_PROFILE
    except (RuntimeError, TypeError, AttributeError):
        return False

def positive(value):
    return type(value) is int and 0 < value < (1 << 63)

def nonnegative(value):
    return type(value) is int and 0 <= value < (1 << 63)

def auth_required(receipt, policy=None):
    policy = password_policy() if policy is None else policy
    return not (policy in ('startup', 'first_access')
        and receipt.get('password_policy_at_auth') == policy
        and receipt.get('key_retained') is True
        and positive(receipt.get('auth_generation'))
        and type(receipt.get('authentication_id')) is str
        and re.fullmatch(r'[0-9a-f]{32}', receipt['authentication_id']) is not None)

def validate_identity(receipt, *, process_check=same_process, mounted=False):
    require(receipt.get('session_reusable') is True
            and receipt.get('profile_id') == EVO_PROFILE
            and receipt.get('credential_type') == 'password',
            message='Reusable credential identity changed')
    require(positive(receipt.get('native_owner_pid'))
            and process_check(receipt['native_owner_pid'], receipt.get('native_owner_starttime')),
            'DECRYPT_REBOOT_REQUIRED', 'The native key owner is no longer live')
    require(nonnegative(receipt.get('native_generation'))
            and nonnegative(receipt.get('native_sequence'))
            and nonnegative(receipt.get('auth_generation'))
            and nonnegative(receipt.get('mount_generation'))
            and type(receipt.get('key_retained')) is bool,
            message='Reusable generation contract changed')
    if receipt['auth_generation'] == 0:
        require(receipt.get('authentication_id') is None and receipt.get('password_policy_at_auth') is None
                and receipt['key_retained'] is False and not mounted,
                message='Never-authenticated session has mixed authentication identity')
    else:
        require(positive(receipt['auth_generation'])
                and positive(receipt['mount_generation'])
                and type(receipt.get('authentication_id')) is str
                and re.fullmatch(r'[0-9a-f]{32}', receipt['authentication_id']) is not None
                and receipt.get('password_policy_at_auth') in POLICIES,
                message='The native authentication epoch is unavailable')
    if mounted:
        require(receipt['key_retained'] is True)
    return receipt

def detached_token(receipt):
    fields = ('schema', 'boot_id', 'run_id', 'supervisor_pid', 'supervisor_starttime',
        'worker_pid', 'worker_starttime', 'physical_volume_token', 'profile_id',
        'credential_type', 'physical_device', 'detached_proof_schema', 'detached_devices', 'owned_crypto_names', *IDENTITY_FIELDS)
    return hashlib.sha256(json.dumps({k: receipt[k] for k in fields},
        sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def block_identity(device):
    """Read one bounded, stable sysfs block identity without querying DM keys."""
    require(type(device) is str and re.fullmatch(r'[0-9]+:[0-9]+', device))
    node = Path('/sys/dev/block') / device
    def snapshot():
        require((node / 'dev').read_text().strip() == device)
        raw = (node / 'uevent').read_text()
        require(len(raw) <= 8192)
        fields = dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
        is_dm = (node / 'dm').is_dir()
        name = (node / 'dm/name').read_text().strip() if is_dm else node.resolve().name
        uuid = (node / 'dm/uuid').read_text().strip() if is_dm else None
        require(0 < len(name) <= 128 and (uuid is None or len(uuid) <= 128))
        slave_dir = node / 'slaves'
        slaves = []
        if slave_dir.is_dir():
            entries = list(slave_dir.iterdir())
            require(len(entries) <= 32)
            slaves = sorted((p / 'dev').read_text().strip() for p in entries)
        require(all(re.fullmatch(r'[0-9]+:[0-9]+', d) for d in slaves)
                and len(slaves) == len(set(slaves)))
        partition = (node / 'partition').is_file()
        physical_leaf = not slaves and (partition and fields.get('DEVTYPE') == 'partition'
            or fields.get('DEVTYPE') == 'disk' and not str(node.resolve()).startswith('/sys/devices/virtual/'))
        require(not is_dm or bool(slaves), message='DM backing chain is unavailable')
        return {'device':device,'name':name,'uuid':uuid,'slaves':slaves,
                'partname':fields.get('PARTNAME'), 'physical_leaf':bool(physical_leaf)}
    before = snapshot()
    require(snapshot() == before, message='Block identity changed while checking unmount')
    return before

def excludes_userdata(device, physical_device, owned_names, *, reader=block_identity):
    """Current backing identity prevents false failures after DM minor reuse."""
    seen = set()
    def visit(current, ancestry):
        require(len(ancestry) < 16 and current not in ancestry and len(seen) < 64,
                message='Block dependency graph is ambiguous or exceeds bounds')
        if current == physical_device:
            return False
        if current in seen:
            return True
        info = reader(current)
        require(type(info) is dict and info.get('device') == current
                and type(info.get('slaves')) is list
                and type(info.get('physical_leaf')) is bool)
        if info.get('partname') == 'userdata' or info.get('name') in owned_names:
            return False
        slaves = info['slaves']
        require(len(slaves) <= 32 and len(set(slaves)) == len(slaves))
        if not slaves:
            require(info['physical_leaf'], message='Cannot determine filesystem backing storage')
        for child in slaves:
            require(type(child) is str and re.fullmatch(r'[0-9]+:[0-9]+', child))
            if not visit(child, ancestry | {current}):
                return False
        # Observe the same current name/UUID/dependency list again after walking.
        require(reader(current) == info, message='Block dependencies changed during unmount proof')
        seen.add(current)
        return True
    return visit(device, set())

def verify_detached(receipt, *, mounts=None, backing_check=excludes_userdata):
    """Prove real filesystem removal, not just disappearance of the Files bind."""
    from decrypt_runtime.mounts import mount_records
    target = '/run/a22x-c-' + receipt['run_id'] + '/root/mnt/userdata-ro'
    worker_mounts = mount_records(Path('/proc', str(receipt['worker_pid']), 'mountinfo').read_text())
    require(not any(m['mountpoint'] == target for m in worker_mounts),
            message='Private userdata filesystem is still mounted')
    if mounts is None:
        from filesystem import all_namespace_mounts
        mounts = all_namespace_mounts()
    devices = receipt.get('detached_devices')
    require(type(devices) is list and 1 <= len(devices) <= 4
            and all(type(v) is str and re.fullmatch(r'[0-9]+:[0-9]+', v) for v in devices))
    require(not any(m.get('mountpoint') == '/mnt/volumes/userdata' for m in mounts),
            message='The public userdata mount survives in a mount namespace')
    # G1's separate read-only source alias is retained with the TEE runtime.
    # These are only this native owner's crypto mappings, not all runtime maps.
    names = receipt.get('owned_crypto_names')
    require(type(names) is list and 2 <= len(names) <= 8
            and len(names) == len(set(names))
            and all(type(n) is str and n.startswith('a22x-data-ro-' + receipt['run_id']) for n in names))
    present = {p.read_text().strip() for p in Path('/sys/block').glob('dm-*/dm/name')}
    require(not present.intersection(names), message='Native userdata crypto mapping remains')
    physical = receipt.get('physical_device')
    require(type(physical) is str and re.fullmatch(r'[0-9]+:[0-9]+', physical))
    block_devices = {m['devno'] for m in mounts if m['devno'].split(':')[0] != '0'}
    require(len(block_devices) <= 256, message='Mount namespace block-device bound exceeded')
    for device in block_devices:
        require(backing_check(device, physical, names),
                message='Userdata remains mounted through a block dependency')
    return True

def validate_detached(receipt, *, boot_id=None, volume_token=None, expected_token=None,
                      process_check=same_process, detached_check=verify_detached):
    from decrypt_runtime.common import SCHEMA as SESSION_SCHEMA
    require(type(receipt) is dict and receipt.get('schema') == SESSION_SCHEMA
            and receipt.get('state') == 'session_unmounted'
            and receipt.get('boot_id') == (boot_id or current_boot()),
            'DECRYPT_REBOOT_REQUIRED', 'The retained session belongs to another boot or state')
    require(process_check(receipt.get('supervisor_pid'), receipt.get('supervisor_starttime'))
            and process_check(receipt.get('worker_pid'), receipt.get('worker_starttime')),
            'DECRYPT_REBOOT_REQUIRED', 'The retained session process identity changed')
    validate_identity(receipt, process_check=process_check)
    require(receipt.get('detached_proof_schema') == 'a22x.ce-session.suspend.v1'
            and receipt.get('filesystem_unmounted') is True
            and receipt.get('ce_authenticated') is False
            and receipt.get('fscrypt_policy_verified') is False
            and receipt.get('session_retained') is True
            and receipt.get('device_offline') is False
            and receipt.get('reboot_required') is False)
    require(volume_token is None or receipt.get('physical_volume_token') == volume_token)
    require(receipt.get('volume_token') == detached_token(receipt)
            and (expected_token is None or expected_token == receipt['volume_token']),
            message='Retained session identity changed')
    detached_check(receipt)
    return receipt
