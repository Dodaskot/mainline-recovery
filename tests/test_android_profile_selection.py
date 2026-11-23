"""Public profile selection and direct NONE mounted response; no device I/O."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import android_decrypt as ad
import android_profiles as profiles
import decrypt_prepare as prep
import decrypt_session as session
from filesystem import FilesystemError


class Context:
    def __init__(self):
        self.events=[]
        self.data={'id':'super-system','container':'super','logical_partition':'system',
            'mounted':False,'mapping':None,'write_supported':False,'volume_token':'system-token',
            'read_only':True,'mount_owner':None,'read_only_guarded':False,'mountpoint':'/public/system'}
    def volume(self, ident, expected=None):
        assert ident=='super-system'
        if expected is not None:assert expected==self.data['volume_token']
        return dict(self.data)
    def mount(self, ident, mode, confirmed, expected):
        assert ident=='super-system' and mode=='ro' and confirmed is False and expected=='system-token'
        self.events.append('mount-ro');self.data.update(mounted=True,mapping='a22x-ro-system',mount_owner='filesystem',read_only_guarded=True)
    def unmount(self, ident, expected):
        assert ident=='super-system' and expected=='system-token'
        self.events.append('unmount');self.data.update(mounted=False,mapping=None,mount_owner=None,read_only_guarded=False)


class ProfileSelectionTests(unittest.TestCase):
    def test_each_exact_pair_selects_and_unmounts_before_return(self):
        for ident,pair in profiles.FRAMEWORK_PINS.items():
            context=Context()
            with patch.object(ad,'framework_pair',return_value=pair),patch.object(ad,'profile',return_value={'profile_id':ident}) as profile:
                self.assertEqual(ad.select_current_profile(context),{'profile_id':ident})
            profile.assert_called_once_with(ident)
            self.assertEqual(context.events,['mount-ro','unmount'])
            self.assertFalse(context.data['mounted'])
    def test_unknown_or_mixed_pair_does_not_select_and_is_unmounted(self):
        for pair in [('0'*64,'1'*64),(profiles.FRAMEWORK_PINS[profiles.SAMSUNG_PROFILE][0],profiles.FRAMEWORK_PINS[profiles.EVO_PROFILE][1])]:
            context=Context()
            with patch.object(ad,'framework_pair',return_value=pair),patch.object(ad,'profile') as profile:
                with self.assertRaises(FilesystemError):ad.select_current_profile(context)
            profile.assert_not_called();self.assertEqual(context.events,['mount-ro','unmount'])
    def test_existing_mount_or_mapping_never_taken_over(self):
        for field,value in [('mounted',True),('mapping','foreign'),('write_supported',True),('logical_partition','vendor')]:
            context=Context();context.data[field]=value
            with self.assertRaises(FilesystemError):ad.select_current_profile(context)
            self.assertEqual(context.events,[])
    def test_read_failure_unmounts(self):
        context=Context()
        with patch.object(ad,'framework_pair',side_effect=OSError('fixture')):
            with self.assertRaises(OSError):ad.select_current_profile(context)
        self.assertEqual(context.events,['mount-ro','unmount'])
    def test_changed_readonly_mount_rejected_before_hash(self):
        context=Context();original=context.mount
        def unsafe(*args):original(*args);context.data['read_only']=False
        context.mount=unsafe
        with patch.object(ad,'framework_pair') as read:
            with self.assertRaises(ValueError):ad.select_current_profile(context)
        read.assert_not_called();self.assertEqual(context.events,['mount-ro','unmount'])
    def test_cleanup_failure_never_returns_selected_profile(self):
        context=Context()
        context.unmount=lambda *a:context.events.append('failed-unmount')
        with patch.object(ad,'framework_pair',return_value=profiles.FRAMEWORK_PINS[profiles.EVO_PROFILE]),patch.object(ad,'profile',return_value={'profile_id':profiles.EVO_PROFILE}):
            with self.assertRaises(ValueError):ad.select_current_profile(context)
    def test_profile_pair_ambiguity_missing_half_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);directory=root/'system/framework';directory.mkdir(parents=True)
            (directory/'services.jar').write_bytes(b'public-services')
            with patch.object(ad.os,'fstatvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)):
                with self.assertRaises(ValueError):ad.framework_pair(root)
                (directory/'framework.jar').write_bytes(b'public-framework')
                self.assertEqual(ad.framework_pair(root),tuple(hashlib.sha256(v).hexdigest() for v in (b'public-services',b'public-framework')))
                other=root/'framework';other.mkdir()
                for name in ('services.jar','framework.jar'):(other/name).write_bytes(b'public')
                with self.assertRaises(ValueError):ad.framework_pair(root)
                for child in other.iterdir():child.unlink()
                other.rmdir();(directory/'framework.jar').unlink();(directory/'framework.jar').symlink_to(directory/'services.jar')
                with self.assertRaises(ValueError):ad.framework_pair(root)
    def test_public_read_requires_ro(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'public.jar';path.write_bytes(b'public')
            with patch.object(ad.os,'fstatvfs',return_value=SimpleNamespace(f_flag=0)):
                with self.assertRaises(ValueError):ad.public_framework_hash(path)
    def test_packaged_profiles_are_paired_not_interchangeable(self):
        for ident in (profiles.SAMSUNG_PROFILE,profiles.EVO_PROFILE):
            p=json.loads((Path(__file__).parents[1]/'profiles/android-decrypt'/(ident+'.json')).read_text())
            self.assertIs(profiles.validate_profile(p,ident),p)
            other=profiles.SAMSUNG_PROFILE if ident==profiles.EVO_PROFILE else profiles.EVO_PROFILE
            with self.assertRaises(ValueError):profiles.validate_profile(p,other)
            for key in ('native_efs_persistence','read_only','credential_discovery'):
                bad=dict(p);bad[key]=int(p[key])
                with self.assertRaises(ValueError):profiles.validate_profile(bad,ident)


class NonePrepareResponseTests(unittest.TestCase):
    def mounted(self):
        return {'id':'userdata','credential_type':'none','decrypt_state':'mounted','mounted':True,
            'read_only':True,'ce_authenticated':True,'fscrypt_policy_verified':True,
            'credential_required':False,'preparation_required':False,'physical_volume_token':'physical'}
    def exercise(self, observed, receipt=None):
        volume={'id':'userdata','volume_token':'physical','decrypt_supported':True,'mounted':False,'external':False}
        context=SimpleNamespace(boot_id='boot',lock_fd=71,volume=lambda ident:observed)
        receipt=receipt or {'profile_id':profiles.EVO_PROFILE,'credential_type':'none','native_efs_persistence':True}
        with patch.object(prep, 'bootstrap_mounts', return_value=[]), patch.object(ad,'select_current_profile',return_value={'profile_id':profiles.EVO_PROFILE}),patch.object(prep,'prepare',return_value=Path('/public/config')),patch.object(ad.subprocess,'Popen') as launch,patch.object(ad,'read_ready',return_value={'ok':True,'state':{'credential_type':'none'}}),patch.object(ad,'session_status',return_value=receipt),patch.object(session,'prepared_status') as pending:
            result=ad.prepare_android(context,volume)
        pending.assert_not_called();args=launch.call_args.args[0]
        self.assertIn('--discover',args);self.assertNotIn('--credential-fd',args)
        return result
    def test_none_returns_verified_mounted_without_credential_channel(self):
        result=self.exercise(self.mounted());self.assertEqual(result['credential_type'],'none');self.assertTrue(result['ce_authenticated'])
    def test_none_rejects_incomplete_or_changed_mount_proof(self):
        for key,value in [('mounted',False),('read_only',False),('ce_authenticated',False),('fscrypt_policy_verified',False),('credential_required',True),('preparation_required',True),('physical_volume_token','stale'),('credential_type','password'),('decrypt_state','awaiting_credential')]:
            observed=self.mounted();observed[key]=value
            with self.assertRaises(FilesystemError):self.exercise(observed)
    def test_neutral_none_requires_current_profile_and_native_efs(self):
        for key,value in [('profile_id',profiles.SAMSUNG_PROFILE),('credential_type','password'),('native_efs_persistence',False)]:
            receipt={'profile_id':profiles.EVO_PROFILE,'credential_type':'none','native_efs_persistence':True};receipt[key]=value
            with self.assertRaises(FilesystemError):self.exercise(self.mounted(),receipt)

if __name__=='__main__':unittest.main(verbosity=2)
