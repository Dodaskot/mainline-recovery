"""Exact public firmware/runtime identities for the two qualified discovery paths."""
SAMSUNG_PROFILE = 'samsung-a226b-a13'
EVO_PROFILE = 'evolutionx-a226b-a16'
LEGACY_EVO_NONE_PROFILE = 'evolutionx-a226b-a16-none'
PROFILES = (SAMSUNG_PROFILE, EVO_PROFILE, LEGACY_EVO_NONE_PROFILE)
EVO_NATIVE_SHA = '3bb66d39fd8006083dbdfdd4434c1f94edfe206a297ed9f5dfe3b97298bf8b71'  # Root replaces after isolated discovery helper build.
GATEKEEPERD_SHA = 'b896d42fff9da2cec02a7211772e8fcfbe5c7a8aead796c252aab1da1c2a628c'
EVO_NAMESPACE = {'image_running_boolean': False, 'native_protector_user_id': 100000, 'native_primary_user_id': 0}
ROOT_MANIFEST_SHA = '7294e951c142f4585f061e6c0d7dc67ed71506599c3122b235ff6de2c6d92e1d'
BUNDLE_SHA = '243883b9c6a248077550a16e6de248eba65053432a73e7c22499131d9623dd8d'  # runtime02 without Samsung vendor files: they come from the phone's vendor (pins only)
KERNEL_BUILD = 152  # exact recovery kernel build (#152: #146 + Tianma native display test, NT36672C dt2w, tzdev idle threads, musb unmap fix)
SOURCE_PACKAGE_SHA = '186e831fe502fb0dbb50c794fba2d41d1d0194743bc079e74e97ceff01f1c5ed'
G4_SHA = '4f2cef1b01ba052894e8dda4667cfcdec4b24901b5ee512503ca4b063196a66b'
NONE_SHA = '5060ff7cdb0ad2e7f695ec8c28354fda3b7a95c773a3699cf47b3614317f90fe'
BOOTSTRAP_SHA = 'd0e08ab8df83dc86ff4f0a11634403cf02afbf82f19091463b48900fe14f3da5'
FRAMEWORK_PINS = {
    SAMSUNG_PROFILE: ('f4795ef0b1f3ebc45e44258b5d9324b52c3148e3ac3158fe02584862d3e9e055',
                     '731db55aa1a0d3a97d28375296cdde04a9a8196028813b15e612c7f39be8e144'),
    EVO_PROFILE: ('ae824be13cfc9f5f7e9673ee9230fdaea5e3fc91230cecbdaf511974c99a533b',
                  '52018a98c6718d17f0c80386d842f1d15bca36b35498e12ecd669e354a34483a'),
}


def validate_profile(p, profile_id):
    if profile_id not in FRAMEWORK_PINS:
        raise ValueError('Unsupported Android profile identity')
    evo = profile_id == EVO_PROFILE
    expected = {
        'schema': 'a22x.android-decrypt.profile.v1', 'profile_id': profile_id,
        'credential_types': ['none', 'password'] if evo else ['password', 'pattern'],
        'credential_discovery': True, 'userdata_filesystem': 'f2fs', 'read_only': True,
        'native_efs_persistence': True, 'bundle_sha256': BUNDLE_SHA,
        'source_package_sha256': SOURCE_PACKAGE_SHA, 'root_manifest_sha256': ROOT_MANIFEST_SHA,
        'framework_services_sha256': FRAMEWORK_PINS[profile_id][0],
        'framework_core_sha256': FRAMEWORK_PINS[profile_id][1],
        'bundle_path': '/opt/a22x-recovery/android-decrypt-runtime.tar',
        'bootstrap_wrapper_sha256': BOOTSTRAP_SHA, 'runtime_member_count': 135,
        'kernel_build': KERNEL_BUILD,
    }
    if evo:
        validate_namespace(p.get('gatekeeper_namespace') if type(p) is dict else None)
        expected.update(gatekeeperd_sha256=GATEKEEPERD_SHA, gatekeeper_namespace=EVO_NAMESPACE)
    if (type(p) is not dict or type(p.get('android_user_id')) is not int
            or p['android_user_id'] != 0 or any(p.get(k) != v for k,v in expected.items())
            or any(type(p.get(k)) is not bool for k in
                   ('read_only','credential_discovery','native_efs_persistence'))):
        raise ValueError('Unqualified Android profile')
    return p


def validate_namespace(value):
    if (type(value) is not dict or set(value) != set(EVO_NAMESPACE)
            or any(type(value[k]) is not type(v) or value[k] != v for k,v in EVO_NAMESPACE.items())):
        raise ValueError('Unqualified current Android Gatekeeper namespace')
    return value


def credential_allowed(profile_id, credential_type):
    return ((profile_id == SAMSUNG_PROFILE and credential_type in ('password', 'pattern'))
            or (profile_id == EVO_PROFILE and credential_type in ('none', 'password'))
            or (profile_id == LEGACY_EVO_NONE_PROFILE and credential_type == 'none'))
