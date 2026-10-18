AA / CA card-side implementation (2026-10-18)
--------------------------------------------
Version 8.0-0.11-chip-auth (code 19) adds live AA and CA handlers in Local travel
document mode. Enable Security information (DG14 / DG15); the Chip test selector
then offers Valid, Bad AA signature and Wrong CA key. Existing BAC/PACE, PA and
optional file selectors remain independent. Match optional groups on the reader.
The preview identifies RSA signing + DH (TD1), or ECDSA signing + ECDH (TD3).

INTERNAL AUTHENTICATE signs an eight-byte challenge using RSA ISO 9796-2 or
ECDSA raw r||s. CA v1 uses MSE KAT or MSE AT/GENERAL AUTHENTICATE, DH/ECDH and
3DES/AES-128/192/256. CA responds through the old channel before installing fresh
keys/SSC zero; the next protected command checks the new channel. Bad AA signature
alters the response; Wrong CA key intentionally derives different channel keys.
Full CA v2 token/nonce mutual authentication, TA and PACE-CAM are not implemented.

Synthetic AA/CA card private keys are intentionally bundled to implement these
operations. They are public development fixtures, not real document keys. Private
CSCA/DSC signing keys are still never saved or shipped. Existing DG14/DG15 bytes,
SOD variants and the public development CSCA are unchanged this round.

Verification: Android JVM tests 18/18; original JMRTD reader 24/24 chip-enabled
scenarios; exact ArkTS reader full matrix 306/306, plus 14/14 chip-only positive/
negative scenarios for each of four CA ciphers; HarmonyOS native XTS/Hypium
1050/1050. Protocol matrices run over local test transports, not NFC. The updated
APK and HAP are installed for the user to perform physical two-phone contact.

The following entries retain earlier rounds' historical scope and results.

DG14 / DG15 security metadata (2026-10-18)
-----------------------------------------
Version 7.0-0.11-security-info (code 18) adds Security information (DG14 / DG15),
default off. Turning it on provides the files and shows a selectable preview.
The HarmonyOS reader has the matching Read security information option. All
three optional flags must match for full PA PASS; COM and SOD have variants
for all eight combinations. Read photo supplies DG2 for its signed hash.

DG14 has CA algorithm/public-key info, CVCA file metadata and (for PACE) a
PACEInfo. TD1 has RSA DG15 / DH CA keys, TD3 EC DG15 / EC CA keys plus ECDSA AA
metadata. RSA AA does not need the ECDSA-specific ActiveAuthenticationInfo.
The preview uses original-Java parsed data, SPKI byte length and SHA-256 so
both screens can be compared. AA/CA remain NOT_CHECKED: no AA/CA APDU handlers
are implemented in this round. Key pairs are synthetic and generated only
in memory; private keys are not saved or shipped.

GenerateSecurityFixtures.java uses the unmodified JMRTD 0.8.9 writers with
BC 1.86 (ASN1Integer(int) is needed by these classes). Protocol reader / SOD
writer processes retain BC 1.79; the actual APK card engine uses BC 1.46.
Regenerating SODs changes the development trust root: regenerate HarmonyOS
vectors, rebuild and install both apps. No original Java artifact was patched.

Verification: original Java reader -> engine 192 scenarios; ArkTS -> same APK
engine 306; Android unit tests 18; HarmonyOS device XTS/Hypium 995 (synthetic
records/native crypto, including four native key imports). Phone contact is
performed by the user. Earlier entries below retain historical scope/results.

DG11 / DG12 additional details (2026-10-18)
----------------------------------------
The local travel-card screen has an independent Additional details (DG11 / DG12)
checkbox (default off). Enabling it also shows a selectable DG11/DG12 preview
on the scrollable home screen. Changing TD1/TD3 or BAC/PACE refreshes the
preview, and disabling the checkbox hides it. Labels and binary byte counts
match the HarmonyOS reader. TD1 fixtures carry full synthetic fields, TD3 partial
fields; both BAC and PACE expose matching files after authentication. COM and
SOD reflect the enabled combination of additional images and details. The
HarmonyOS reader has a matching Read additional details option. Enable Read
photo and Verify SOD / PA for complete fixture verification; match both optional
flags for a six-group PASS. CAN 123456 is available with PACE.

GenerateDetailFixtures.java uses the unmodified JMRTD 0.8.9 writers. Existing
GenerateSODFixtures.java now signs all four optional-group combinations, including
valid / altered DG1 / bad signature / untrusted CSCA scenarios. Private keys are
never saved. Regenerating SODs changes the development CSCA: resync HarmonyOS
PA vectors and its public demo root, rebuild, and install both updated apps.
Version 6.1-0.11-details-preview (code 17) adds the home-screen preview.
GenerateDetailFixtures reads the actual served binary files through original
JMRTD before writing details-preview-*.txt. Its --preview-only option updates
only preview text, preserving card data, SODs and development certificates.
Independent original Java reader regression: 96 scenarios; ArkTS reader against
the same APK engine: 154 scenarios. These are loopback protocol tests, not NFC
or UI automation. HarmonyOS device XTS: 852/852 with synthetic inputs and native
crypto. Detail image fields are raw bytes; the reader demo shows byte counts.

Earlier entries below retain their historical scope and validation counts.

# Standalone travel-document test card

Base: `virtualsmartcard-0.11`, commit `82bc5ad066b26ee057d2af200c1a66e3a65a9743`.
Development branch: `0.11-android-standalone`.

The Android APK now includes a card-side Java implementation. Its **Local travel
document** mode needs no Windows process, TCP connection, or Google Play services.
The original Java Card and Remote Virtual Smart Card modes remain in Settings.
The application ID is `com.vsmartcard.acardemulator.standalone.debug` for the full
debug build, with launcher name **Travel Card 0.11 Debug**; it can coexist with
Smart Card Emulator Debug.

## Optional displayed images (version 5.0)

Enable **Additional images (DG5 / DG7)** on the main page to serve displayed
portrait and signature/mark data, in addition to DG1/DG2. The default is off.
The previews show synthetic labeled JPEGs generated and encoded by original
JMRTD 0.8.9; no real portraits or signatures are used. Each TD1/TD3 + BAC/PACE
combination has its own pair (DG5 160x120, DG7 240x80).

The option switches COM and SOD together: COM advertises DG1/DG2/DG5/DG7,
and SOD signs all four encoded groups. All existing PA error scenarios also
have an additional-images variant. Enable the matching HarmonyOS
**Read additional images (DG5 / DG7)** switch to display and verify them.
If the groups are signed but not read, PA must report NOT_CHECKED / INDETERMINATE.

The test CSCA was regenerated for the new signed variants; install both updated
APK and HAP. Only public certificates/signatures are stored; signing private
keys are never saved or shipped. The original two-group option keeps its COM
and two-group SOD behavior. Both MF SELECT encodings (no data and explicit 3F00)
are accepted. DG5/DG7 have FIDs 0105/0107 and SFIs 05/07.

Verification for this update: 48 original-JMRTD reader scenarios and 78 exact
ArkTS reader scenarios against the APK engine, without RF. The latter includes
SFI reads, length correction, correct/wrong CAN and enabled/disabled images.
The Gradle unit suite and full debug APK build pass.

## Test cards

| Format | Document number | Birth | Expiry |
| --- | --- | --- | --- |
| TD1 | D23145890 | 740812 | 120415 |
| TD3 | L898902C3 | 740812 | 120415 |

Choose the format and access control on the home screen. Both formats support
BAC with 3DES secure messaging, or PACE with AES secure messaging. PACE advertises
only ECDH-GM / BrainpoolP256r1 (parameter 13) / AES-CBC-CMAC-128 (OID
`0.4.0.127.0.7.2.2.4.2.2`), accepting MRZ or CAN `123456`. PACE mode rejects BAC.
All data is a public fictional ICAO example. The expired fixture dates are
intentional; enter them exactly in the reader.

Files: EF.CardAccess in PACE mode, EF.COM, DG1, DG2 and EF.SOD. Each format/access-control
combination has its own 160x120 labeled JPEG test pattern:

| Combination | Color | Image label |
| --- | --- | --- |
| TD1 + BAC | Blue | TD1 / BAC / DG2 TEST 1 |
| TD1 + PACE | Green | TD1 / PACE / DG2 TEST 2 |
| TD3 + BAC | Orange | TD3 / BAC / DG2 TEST 3 |
| TD3 + PACE | Purple | TD3 / PACE / DG2 TEST 4 |

The home preview and the served DG2 change together when either selector changes.
Turn **Read photo ON** in the HarmonyOS demo to display it. JPEG2000,
AA, EAC and other PACE algorithms are outside this increment.

The home PA selector has four scenarios: Valid, Altered DG1, Bad signature and
Untrusted CSCA. EF.SOD (FID 011D / SFI 1D) contains SHA-256 hashes of the exact
encoded DG1/DG2 and a CMS RSA/SHA-256 signature from a test document signer.
The public development CSCA is `mrtd/test-csca.der`; it is not a government root.
The alternative untrusted signer has a different test CSCA. Altered DG1 changes
the surname without changing the access credentials. Bad signature flips one
signature byte while preserving valid ASN.1. None of these scenarios changes
BAC/PACE or the photo. COM still lists DG1/DG2 only; SOD is not a data group.

`verification/GenerateSODFixtures.java` uses unmodified JMRTD 0.8.9 and BC 1.79
to create the SODs and test CSCA/DSC certificates, valid 2020-2040. Private keys
exist only during generation; they are not saved or packaged. Public PA vectors
are under `verification/fixtures/pa`. All trust checks require an explicitly
configured root; the certificate embedded in SOD does not establish trust.

`verification/GenerateDG2Fixtures.java` draws the four original test patterns;
`verification/GenerateDG2Fixture.java` wraps each using unmodified JMRTD 0.8.9.
The generated JPEGs are under `verification/fixtures/photo-<format>-<method>.jpg`.
Each DG2 is bundled as `mrtd/dg2-<format>-<method>.bin`, so no network or external
file access is needed. Fixture metadata and hashes are recorded in
`verification/fixtures/photo.json`. The generator writes the home preview
`res/drawable-nodpi/dg2_<format>_<method>.jpg` from the same JPEG bytes.
EF.COM declares both DG1 and DG2; file ID 0102 and SFI 02 select the photo.
Protected reads above 223 bytes return authenticated 6CDF, allowing the reader
to retry at 223 bytes without exceeding short-APDU response capacity. The
existing HarmonyOS reader already handles this length correction.

Keep the emulator in the foreground, screen unlocked and NFC enabled. On Xiaomi,
use the previously verified host-based NFC routing setting (the test phone used
Google Pay as its selected card app). The foreground HCE preference does not
necessarily override a manufacturer's secure-element routing setting. Move the
phones apart before switching format/mode or restarting a failed reader attempt.
The card clears its authenticated session on NFC deactivation or Reset card.

## Build and verification

Build requirements remain JDK 17, Android SDK 34, and the six Android source
submodules pinned by this tag. Initialize them with:

```powershell
git submodule update --init -- ACardEmulator/app/src/main/external
cd ACardEmulator
.\Build-Standalone.ps1
```

The script runs the 18 JVM tests (6 migrated network tests, 12 card/crypto tests),
builds the full debug APK and copies it to `build/standalone/TravelCard-0.11-debug.apk`.
To also install and launch only the main activity on an explicitly selected phone:

```powershell
.\Build-Standalone.ps1 -Install -Serial YOUR_ANDROID_SERIAL
```

Independent protocol regression uses the unmodified JMRTD 0.8.9 reader and BC
1.79 in one JVM, and the exact APK card source and its existing BC 1.46 dependency
in another JVM. This keeps the reader and card implementations independent.
It covers TD1/TD3 × BAC-MRZ/PACE-MRZ/PACE-CAN: wrong-key rejection, CardAccess,
COM/DG1/DG2/SOD parsing, exact JPEG payload and decode, data hashes, CMS signature,
native Java PKIX, multi-block reads and length
correction, short-response size limits, protected errors, plaintext rejection,
MAC tampering, replay, recovery and link-reset invalidation. It uses local Gradle
artifacts:

```powershell
python .\verification\verify-standalone.py
```

To regenerate all four patterns, DG2 files, previews and metadata, then verify:

```powershell
python .\verification\verify-standalone.py --regenerate-photos
```

Host checks cover all six access scenarios times four PA scenarios (24 total).
The user manually confirmed TD1/TD3 x BAC/PACE with the four labeled DG2 images.
The new SOD/PA RF flow remains to be checked with the HarmonyOS phone; no
HarmonyOS device was accessed for this increment. No real identity or private
key is included.

On 2026-10-17, Android headless instrumentation passed 24 native RSA/PKIX checks,
including tampered DG1, bad signature, untrusted issuer, no root and expiry.
It does not start an activity, change settings or use NFC. Build it using
`:app:assembleFullDebugAndroidTest`, install both main and test APKs on an
explicitly selected phone, then run:

```powershell
adb -s YOUR_ANDROID_SERIAL shell am instrument -w com.vsmartcard.acardemulator.standalone.debug.test/com.vsmartcard.acardemulator.verification.PAInstrumentation
```

To regenerate certificates/SODs use `--regenerate-sod`. Regenerating photos also
regenerates SODs. This creates a new development root: rebuild the Android APK
and run HarmonyOS `verification/generate.py` (also done by its build script) to
resync the public root and test vectors before building the matching HAP.
The APK retains the upstream BC dependency for Java Card compatibility and is a
test fixture, not a credential-issuing or production security component.

## Migrated changes

Passport AID `A0000002471001`, foreground HCE preference, asynchronous APDU
dispatch with transaction generation checks, TCP timeouts/framing/error handling,
debug build identification and six network regressions were brought over from
the previously tested Android checkout. Local-card changes are isolated under
`emulators/mrtd`; Android transport and optional remote-card code stay separate.

License: GPL-3.0-or-later, as with ACardEmulator. Existing third-party dependencies
retain their own licenses.
