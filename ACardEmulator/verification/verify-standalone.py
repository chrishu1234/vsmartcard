"""Independent protocol regression. Uses local Gradle artifacts; no phone/backend."""
from pathlib import Path
import os
import subprocess
import shutil
import argparse
import json
import hashlib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--regenerate-photos', action='store_true', help='Regenerate all four labeled JPEG, DG2 and preview fixtures.')
parser.add_argument('--regenerate-sod', action='store_true', help='Generate new test certificates and SODs; then resync HarmonyOS PA fixtures.')
parser.add_argument('--generate-fixtures-only', action='store_true', help='Generate requested fixtures without running the reader matrix.')
args = parser.parse_args()

ROOT = Path(__file__).resolve().parents[1]
CACHE = Path.home() / '.gradle/caches/modules-2/files-2.1'
CLASSES = ROOT / 'build/standalone-verification'
CLASSES.mkdir(parents=True, exist_ok=True)
JAVA_HOME = Path(os.environ.get('JAVA_HOME', r'C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot'))
JAVA = str(JAVA_HOME / 'bin/java.exe') if os.name == 'nt' else shutil.which('java')
JAVAC = str(JAVA_HOME / 'bin/javac.exe') if os.name == 'nt' else shutil.which('javac')

def artifact(coordinate, filename):
    matches = list((CACHE / coordinate).glob('*/' + filename))
    if len(matches) != 1:
        raise RuntimeError('Missing or ambiguous local artifact: ' + filename)
    return str(matches[0])

old_bc = artifact('org.bouncycastle/bcprov-jdk14/1.46', 'bcprov-jdk14-1.46.jar')
oracle_jars = [artifact(p, n) for p, n in [
    ('org.jmrtd/jmrtd/0.8.9', 'jmrtd-0.8.9.jar'),
    ('net.sf.scuba/scuba-smartcards/0.0.21', 'scuba-smartcards-0.0.21.jar'),
    ('org.bouncycastle/bcprov-jdk18on/1.79', 'bcprov-jdk18on-1.79.jar'),
    ('org.bouncycastle/bcutil-jdk18on/1.79', 'bcutil-jdk18on-1.79.jar'),
    ('org.bouncycastle/bcpkix-jdk18on/1.79', 'bcpkix-jdk18on-1.79.jar'),
]]
sources = ROOT / 'app/src/main/java/com/vsmartcard/acardemulator/emulators'
subprocess.run([JAVAC, '-cp', old_bc, '-d', str(CLASSES), str(sources / 'Emulator.java'),
                *map(str, (sources / 'mrtd').glob('*.java')), str(ROOT / 'verification/StandaloneCardServer.java')], check=True)
oracle_cp = os.pathsep.join([str(CLASSES), *oracle_jars])
if args.regenerate_photos:
    subprocess.run([JAVAC, '-cp', oracle_cp, '-d', str(CLASSES), str(ROOT / 'verification/GenerateDG2Fixture.java'), str(ROOT / 'verification/GenerateDG2Fixtures.java'), str(ROOT / 'verification/GenerateDisplayedFixtures.java')], check=True)
    subprocess.run([JAVA, '-Djava.awt.headless=true', '-cp', oracle_cp, 'GenerateDG2Fixtures', str(ROOT)], check=True)
    subprocess.run([JAVA, '-Djava.awt.headless=true', '-cp', oracle_cp, 'GenerateDisplayedFixtures', str(ROOT)], check=True)
if args.regenerate_sod or args.regenerate_photos:
    # DG14 writers in the published 0.8.9 artifact call ASN1Integer(int), added in BC 1.86.
    security_cp=os.pathsep.join([str(CLASSES),*oracle_jars[:2],artifact('org.bouncycastle/bcprov-jdk18on/1.86','bcprov-jdk18on-1.86.jar'),artifact('org.bouncycastle/bcutil-jdk18on/1.86','bcutil-jdk18on-1.86.jar')])
    subprocess.run([JAVAC, '-encoding','UTF-8','-cp', oracle_cp, '-d', str(CLASSES), str(ROOT/'verification/GenerateDetailFixtures.java')],check=True)
    subprocess.run([JAVA, '-cp', oracle_cp, 'GenerateDetailFixtures', str(ROOT)],check=True)
    subprocess.run([JAVAC, '-encoding','UTF-8','-cp',security_cp,'-d',str(CLASSES),str(ROOT/'verification/GenerateSecurityFixtures.java')],check=True)
    subprocess.run([JAVA,'-cp',security_cp,'GenerateSecurityFixtures',str(ROOT)],check=True)
    subprocess.run([JAVAC, '-cp', oracle_cp, '-d', str(CLASSES), str(ROOT / 'verification/GenerateSODFixtures.java')], check=True)
    subprocess.run([JAVA, '-cp', oracle_cp, 'GenerateSODFixtures', str(ROOT)], check=True)
if args.generate_fixtures_only:
    if not (args.regenerate_sod or args.regenerate_photos): parser.error('--generate-fixtures-only requires a regeneration flag')
    raise SystemExit(0)
photo_manifest = json.loads((ROOT / 'verification/fixtures/photo.json').read_text(encoding='utf-8'))
assert len(photo_manifest['fixtures']) == 4
assert len({photo['jpegSHA256'] for photo in photo_manifest['fixtures']}) == 4, 'Photo fixtures must differ'
for photo in photo_manifest['fixtures']:
    name = photo['id']
    jpeg = (ROOT / f'verification/fixtures/photo-{name}.jpg').read_bytes()
    preview = (ROOT / f'app/src/main/res/drawable-nodpi/dg2_{name.replace("-", "_")}.jpg').read_bytes()
    dg2 = (ROOT / f'app/src/main/resources/mrtd/dg2-{name}.bin').read_bytes()
    assert jpeg == preview and hashlib.sha256(jpeg).hexdigest() == photo['jpegSHA256'], f'{name} preview mismatch'
    assert hashlib.sha256(dg2).hexdigest() == photo['dg2SHA256'], f'{name} DG2 mismatch'
subprocess.run([JAVAC, '-encoding', 'UTF-8', '-cp', oracle_cp, '-d', str(CLASSES), str(ROOT / 'verification/StandaloneReaderOracle.java')], check=True)
passed = 0
for security in (False, True):
    for details in (False, True):
        for displayed in (False, True):
            for format_name in ('TD1', 'TD3'):
                for mode, key, pa in [(mode, key, pa) for mode, key in (('BAC', 'MRZ'), ('PACE', 'MRZ'), ('PACE', 'CAN'))
                                      for pa in ('Valid', 'Altered DG1', 'Bad signature', 'Untrusted CSCA')]:
                    server = subprocess.Popen([JAVA, '-cp', os.pathsep.join([str(CLASSES), str(ROOT / 'app/src/main/resources'), old_bc]), 'StandaloneCardServer', format_name, mode, pa, 'displayed' if displayed else 'plain', 'details' if details else 'plain', 'security' if security else 'plain'],
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        line = server.stdout.readline().strip()
                        if not line.isdigit():
                            raise RuntimeError('Card process failed: ' + line + server.stderr.read())
                        photo = ROOT / f'verification/fixtures/photo-{format_name.lower()}-{mode.lower()}.jpg'
                        result = subprocess.run([JAVA, '-cp', oracle_cp, 'StandaloneReaderOracle', line, format_name, mode, key, str(photo), pa, str(ROOT / 'app/src/main/resources/mrtd/test-csca.der'), 'displayed' if displayed else 'plain', 'details' if details else 'plain', 'security' if security else 'plain'],
                                                capture_output=True, text=True, timeout=40)
                        print(result.stdout, end='', flush=True)
                        if result.returncode:
                            print(result.stderr, end='', flush=True)
                            raise RuntimeError(f'{format_name} {mode} {key} failed')
                        server.wait(timeout=5)
                        if server.returncode:
                            raise RuntimeError(server.stderr.read())
                        passed += 1
                    finally:
                        if server.poll() is None:
                            server.terminate()
                            try:
                                server.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                server.kill()
                                server.wait(timeout=5)
print(f'PASS {passed} independent JMRTD scenarios')
