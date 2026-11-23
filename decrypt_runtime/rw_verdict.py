"""Bounded public RW proof parser; no RO receipt can authorize writable CE."""
import re
from decrypt_runtime.ro_auth_callback_session import classify as classify_ro, require, AUTH_FAIL

PASS = re.compile(rb'G4 CE_RW_SESSION_PASS version=1 old_removed=1 new_live=1 new_creator=([1-9][0-9]{0,9}) fs_ro=0 dm_ro=0 alias_ro=0 ce_policy=1 quota_user_group=1 media_read=1')
FAIL = re.compile(rb'G4 CE_RW_SESSION_FAILED version=1 phase=([a-z_]{1,40}) errno=([1-9][0-9]{0,9}) old_removed=([01]) new_attempted=([01]) new_live=([01]) new_creator=([1-9][0-9]{0,9}) cleanup_errno=([0-9]{1,10})')
REJECT = re.compile(rb'G4 CE_RW_SESSION_REJECTED version=1 phase=beforeauth errno=([1-9][0-9]{0,9}) old_removed=0 new_attempted=0 new_live=0 new_creator=([1-9][0-9]{0,9})')
CLEAN_PASS = re.compile(rb'G4 CE_RW_CLEANUP_PASS version=1 creator=([1-9][0-9]{0,9}) new_live=0')
CLEAN_FAIL = re.compile(rb'G4 CE_RW_CLEANUP_FAILED version=1 creator=([1-9][0-9]{0,9}) errno=([1-9][0-9]{0,9})')
RO_MEDIA = re.compile(rb'G4 SP_MEDIA_USER0_READDIR_PASS entries=([0-9]{1,4}) complete=([01]) fs_ro=1 dm_ro=([01]) alias_ro=([01])')
RW_MEDIA = re.compile(rb'G4 CE_RW_MEDIA_PASS entries=([0-9]{1,4}) complete=([01])')
WP_PATTERNS = tuple(re.compile(p) for p in (
    rb'G4 WP_(?:KERNEL_RO_RECOVERY_CHECK|INITIAL_FS_RO_DM_RW)_PASS dm=(a22x-data-ro-[a-z0-9]{8,26}) raw_dm=\1-raw device=[0-9]{1,10}:[0-9]{1,10} sectors=[1-9][0-9]{0,19}',
    rb'G4 WP_F2FS_STATUS sb=0x[0-9a-f]{1,16} cp=0x[0-9a-f]{1,16} clean_required=0',
    rb'G4 WP_F2FS_HEALTH_PASS clean_checkpoint=0'))
WP_LITERALS = frozenset()
PATTERNS=(PASS,FAIL,REJECT,CLEAN_PASS,CLEAN_FAIL,RO_MEDIA,RW_MEDIA)


def classify(stdout, stderr, evo=False):
    if evo:
        from decrypt_runtime.ro_evox_callback_session import classify as selected_ro
    else:
        selected_ro=classify_ro
    require(type(stdout) is bytes and type(stderr) is bytes and len(stdout)<=8192 and len(stderr)<=8192,'RW public output exceeds bound')
    result={'status_lines':[],'linker_warnings':0}
    for line in stdout.splitlines()+stderr.splitlines():
        if line in WP_LITERALS or any(p.fullmatch(line) for p in PATTERNS+WP_PATTERNS):
            result['status_lines'].append(line.decode('ascii'))
        else:
            original=selected_ro(line+b'\n',b'')
            result['status_lines'].extend(original['status_lines'])
            result['linker_warnings']+=original['linker_warnings']
    return result


def matches(pattern, lines):
    return [m for line in lines if (m:=pattern.fullmatch(line.encode('ascii'))) is not None]


def native_verdict(record):
    require(record['operation'] in ('unlock-sp-user0-rw','unlock-evox-password-user0-rw'),'Wrong RW native operation')
    evo = record['operation'] == 'unlock-evox-password-user0-rw'
    key_marker = 'G4 EVOX_PASSWORD_KEY_RECEIVED_ONCE bytes=64' if evo else 'G4 SP_KEY_RECEIVED_ONCE bytes=64'
    other_marker = 'G4 SP_KEY_RECEIVED_ONCE bytes=64' if evo else 'G4 EVOX_PASSWORD_KEY_RECEIVED_ONCE bytes=64'
    require(type(record.get('returncode')) is int, 'RW native completion type')
    lines=record['status_lines']
    passes,failures,rejections=(matches(p,lines) for p in (PASS,FAIL,REJECT))
    require(len(passes)+len(failures)+len(rejections)==1,'Missing/duplicate RW native verdict')
    rwmedia=matches(RW_MEDIA,lines)
    if record['returncode']==0:
        require(len(passes)==1 and int(passes[0][1])==record['pid'],'RW creator identity mismatch')
        require(not any('FAILED' in x or 'MISMATCH' in x or 'REJECTED' in x for x in lines),
                'Conflicting RW native success')
        require(lines.count('G3 SP_CE_AUTHENTICATED_KEY_DELIVERED')==1
            and lines.count(key_marker)==1 and other_marker not in lines
            and lines.count('G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS')==4,'RW native CE admission proof missing')
        require(sum(x.startswith('G4 WP_KERNEL_RO_RECOVERY_CHECK_PASS ') for x in lines)==1
            and sum(x.startswith('G4 WP_INITIAL_FS_RO_DM_RW_PASS ') for x in lines)==1,
            'Fresh RO preflight or RW device-chain proof missing')
        ro=matches(RO_MEDIA,lines)
        require(len(ro)==2 and sorted((int(m[3]),int(m[4])) for m in ro)==[(0,0),(1,1)]
            and all(int(m[1])<=4096 and m[2]==b'1' for m in ro),'RW double RO proof incomplete')
        require(len(rwmedia)==1 and int(rwmedia[0][1])<=4096 and rwmedia[0][2]==b'1',
                'RW media proof incomplete')
        return dict(status='PASSWORD_CE_RW_MEDIA_PASS',success=True,failure_stage=None,
            old_removed=True,new_attempted=True,new_live=True,new_creator=record['pid'],cleanup_errno=0)
    require(not passes and not rwmedia,'Conflicting RW failure evidence')
    if failures:
        m=failures[0]
        require(int(m[6])==record['pid'] and int(m[2])<=0x7fffffff
            and int(m[7])<=0x7fffffff and (m[4]==b'0' or m[3]==b'1')
            and (m[5]==b'0' or m[4]==b'1'),'RW failure ownership fields invalid')
        result=dict(status='PASSWORD_CE_RW_NATIVE_FAILED_NO_RETRY',success=False,
            failure_stage='native',old_removed=m[3]==b'1',new_attempted=m[4]==b'1',
            new_live=m[5]==b'1',new_creator=int(m[6]),cleanup_errno=int(m[7]))
    else:
        m=rejections[0]
        require(int(m[2])==record['pid'] and int(m[1])<=0x7fffffff,'RW rejection identity invalid')
        result=dict(status='PASSWORD_CE_RW_REJECTED_NO_RETRY',success=False,failure_stage='native',
            old_removed=False,new_attempted=False,new_live=False,new_creator=int(m[2]),cleanup_errno=0)
    auth=matches(AUTH_FAIL,lines)
    require(len(auth)<=1,'Duplicate RW authentication verdict')
    if auth:
        m=auth[0]
        require(result['old_removed'] and not result['new_attempted']
            and not result['new_live'] and result['cleanup_errno']==0
            and 'G3 SP_CE_AUTHENTICATED_KEY_DELIVERED' not in lines
            and int(m[2])<=0xffffffff and int(m[3])<=0xffffffff,'Auth failure reached write transition')
        result.update(status='PASSWORD_AUTH_FAILED_NO_RETRY',
            failure_stage='protector' if m[1]==b'AUTH' else 'primary',
            native_auth_status=int(m[2]),native_timeout_ms=int(m[3]))
    return result


def cleanup_verdict(record, creator):
    require(record['operation']=='cleanup-rw' and record['returncode']==0,'RW normal cleanup failed')
    passed=matches(CLEAN_PASS,record['status_lines'])
    require(len(passed)==1 and int(passed[0][1])==creator
        and not matches(CLEAN_FAIL,record['status_lines']),'RW cleanup ownership proof missing')
    return True
