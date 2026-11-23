#!/usr/bin/env python3
"""Build migration_agent.dex (tools/migration_agent, run on the new Android by app_process).

    tools/build_migration_agent.py --android-jar SDK/platforms/android-35/android.jar --d8 SDK/build-tools/35.0.0/d8

javac --release 11 against android.jar, then d8 --min-api 30; the dex lands beside the helpers."""
import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--android-jar', type=Path, required=True)
    parser.add_argument('--d8', type=Path, required=True)
    args = parser.parse_args()
    sources = sorted((ROOT / 'tools/migration_agent').rglob('*.java'))
    with tempfile.TemporaryDirectory(prefix='a22x-agent-') as tmp:
        classes, dex = Path(tmp) / 'classes', Path(tmp) / 'dex'
        classes.mkdir()
        dex.mkdir()
        subprocess.run(['javac', '--release', '11', '-classpath', str(args.android_jar), '-d', str(classes), *map(str, sources)],
                       check=True)
        subprocess.run([str(args.d8), '--min-api', '30', '--lib', str(args.android_jar), '--output', str(dex),
                        *map(str, sorted(classes.rglob('*.class')))], check=True)
        (ROOT / 'migration_agent.dex').write_bytes((dex / 'classes.dex').read_bytes())
    print(ROOT / 'migration_agent.dex')


if __name__ == '__main__':
    main()
