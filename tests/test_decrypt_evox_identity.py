"""Exact firmware layout identity guards; synthetic public files, no device I/O."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from decrypt_runtime import ro_evox_callback_session as cb

DIGESTS={b'SERVICES':'ae824be13cfc9f5f7e9673ee9230fdaea5e3fc91230cecbdaf511974c99a533b',
         b'FRAMEWORK':'52018a98c6718d17f0c80386d842f1d15bca36b35498e12ecd669e354a34483a',
         b'GATEKEEPER':cb.GATEKEEPERD_SHA}
class Digest:
    def __init__(self,data=b''):self.data=bytearray(data)
    def update(self,data):self.data.extend(data)
    def hexdigest(self):return DIGESTS.get(bytes(self.data),'0'*64)

class LayoutIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.stock=self.root/'mnt/system_stock'
        self.stock.mkdir(parents=True)
        self.runtime=SimpleNamespace(backend=SimpleNamespace(at=lambda p:self.root/p.lstrip('/')))
    def layout(self,relative='system'):
        root=self.stock/relative if relative else self.stock
        (root/'framework').mkdir(parents=True,exist_ok=True);(root/'bin').mkdir(parents=True,exist_ok=True)
        (root/'framework/services.jar').write_bytes(b'SERVICES')
        (root/'framework/framework.jar').write_bytes(b'FRAMEWORK')
        (root/'bin/gatekeeperd').write_bytes(b'GATEKEEPER')
        return root
    def verify(self):
        events=[]
        with patch('hashlib.sha256',side_effect=Digest),patch.object(cb.os,'fstatvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)),patch.object(cb.os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)):
            cb.current_framework_identity(self.runtime,lambda event,**fields:events.append((event,fields)))
        return events
    def test_actual_sar_canonical_system_layout_ignores_unused_bin_alias(self):
        self.layout();(self.stock/'bin').symlink_to('/system/bin')
        self.assertEqual(len(self.verify()),2)
    def test_flat_system_layout_remains_exact_and_supported(self):
        self.layout('');self.assertEqual(len(self.verify()),2)
    def test_selected_gatekeeper_symlink_rejected(self):
        root=self.layout();p=root/'bin/gatekeeperd';p.unlink();p.symlink_to(root/'framework/services.jar')
        with self.assertRaisesRegex(RuntimeError,'SYMLINK_PATH'):self.verify()
    def test_mixed_jar_roots_rejected_before_gatekeeper(self):
        root=self.layout();(root/'framework/framework.jar').unlink()
        (self.stock/'framework').mkdir();(self.stock/'framework/framework.jar').write_bytes(b'FRAMEWORK')
        with self.assertRaisesRegex(RuntimeError,'FRAMEWORK_LAYOUT_MISMATCH'):self.verify()
    def test_duplicate_complete_layouts_rejected(self):
        self.layout();self.layout('')
        with self.assertRaisesRegex(RuntimeError,'framework identity mismatch'):self.verify()
    def test_wrong_selected_gatekeeper_hash_rejected(self):
        root=self.layout();(root/'bin/gatekeeperd').write_bytes(b'WRONG')
        with self.assertRaisesRegex(RuntimeError,'CURRENT_GATEKEEPERD_IDENTITY'):self.verify()
    def test_selected_gatekeeper_nonreadonly_view_rejected(self):
        self.layout()
        with patch('hashlib.sha256',side_effect=Digest),patch.object(cb.os,'fstatvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)),patch.object(cb.os,'statvfs',return_value=SimpleNamespace(f_flag=0)):
            with self.assertRaisesRegex(RuntimeError,'Gatekeeper binary view not read-only'):
                cb.current_framework_identity(self.runtime,lambda *a,**k:None)

if __name__=='__main__':unittest.main(verbosity=2)
