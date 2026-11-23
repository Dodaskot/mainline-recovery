#!/usr/bin/env python3
"""Package verified workspace XML as a no-network, read-only Android layout provider."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile


def build(xml, apk, tools, platform):
    data = xml.read_bytes()
    if len(data) > 4 << 20 or ET.fromstring(data).tag != 'workspace':
        raise ValueError('Expected a Launcher3 workspace XML document of at most 4 MiB')
    package = 'org.a22x.workspace.p' + hashlib.sha256(data).hexdigest()[:24]
    with tempfile.TemporaryDirectory(dir=apk.parent) as tmp:
        root = Path(tmp)
        for name in ('assets', 'classes', 'dex'):
            (root / name).mkdir()
        (root / 'assets/workspace.xml').write_bytes(data)
        (root / 'AndroidManifest.xml').write_text(f"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}" android:versionCode="1" android:versionName="1">
          <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>
          <queries><intent><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.HOME"/></intent></queries>
          <application android:label="A22x workspace layout" android:allowBackup="false">
            <provider android:name="org.a22x.workspace.LayoutProvider" android:authorities="{package}" android:exported="true"/>
          </application></manifest>""")
        def run(*args):
            subprocess.run(args, cwd=root, check=True)

        run(tools / 'aapt2', 'link', '-o', 'resources.apk', '-I', platform, '--manifest',
            'AndroidManifest.xml', '-A', 'assets', '-0', 'xml')
        run('javac', '-source', '8', '-target', '8', '-bootclasspath', platform, '-d', 'classes',
            Path(__file__).resolve().with_name('LayoutProvider.java'))
        run(tools / 'd8', '--min-api', '28', '--lib', platform, '--output', 'dex',
            *sorted((root / 'classes').rglob('*.class')))
        with zipfile.ZipFile(root / 'resources.apk', 'a', zipfile.ZIP_DEFLATED) as archive:
            archive.write(root / 'dex/classes.dex', 'classes.dex')
        run(tools / 'zipalign', '-p', '4', 'resources.apk', 'aligned.apk')
        (root / 'password').write_text(secrets.token_urlsafe(32))
        run('keytool', '-genkeypair', '-alias', 'layout', '-keyalg', 'RSA', '-keysize', '2048',
            '-keystore', 'ephemeral.p12', '-storepass:file', 'password', '-keypass:file', 'password',
            '-dname', 'CN=Local Android Layout', '-validity', '3650')
        run(tools / 'apksigner', 'sign', '--ks', 'ephemeral.p12', '--ks-pass', 'file:password',
            '--out', 'layout.apk', 'aligned.apk')
        run(tools / 'apksigner', 'verify', 'layout.apk')
        signed = root / 'layout.apk'
        signed.chmod(0o600)
        os.link(signed, apk)
    return package


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build-tools', required=True, type=Path)
    p.add_argument('--android-jar', required=True, type=Path)
    p.add_argument('layout_xml', type=Path)
    p.add_argument('new_apk', type=Path)
    a = p.parse_args()
    print(json.dumps({'authority': build(a.layout_xml, a.new_apk, a.build_tools.resolve(), a.android_jar.resolve())}))
