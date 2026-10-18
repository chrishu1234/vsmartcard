param(
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$SdkRoot = $env:ANDROID_HOME,
    [switch]$Install,
    [string]$Serial
)
$ErrorActionPreference = 'Stop'
if (-not $JavaHome) { $JavaHome = 'C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot' }
if (-not $SdkRoot) { $SdkRoot = Join-Path $env:LOCALAPPDATA 'Android\sdk' }
if (-not (Test-Path -LiteralPath (Join-Path $JavaHome 'bin\java.exe'))) { throw 'Set -JavaHome to a JDK 17 directory.' }
if (-not (Test-Path -LiteralPath (Join-Path $SdkRoot 'platforms\android-34\android.jar'))) { throw 'Set -SdkRoot to an Android SDK containing API 34.' }
if ($Install -and -not $Serial) { throw '-Install requires an explicit -Serial.' }
$savedJava = $env:JAVA_HOME
$savedAndroid = $env:ANDROID_HOME
$savedSdk = $env:ANDROID_SDK_ROOT
Push-Location $PSScriptRoot
try {
    $env:JAVA_HOME = $JavaHome
    $env:ANDROID_HOME = $SdkRoot
    $env:ANDROID_SDK_ROOT = $SdkRoot
    & .\gradlew.bat :app:testFullDebugUnitTest :app:assembleFullDebug --console=plain --no-daemon
    if ($LASTEXITCODE -ne 0) { throw 'Tests or APK build failed.' }
    $apkDirectory = Join-Path $PSScriptRoot 'app\build\outputs\apk\full\debug'
    $apkMetadata = Get-Content -Raw -LiteralPath (Join-Path $apkDirectory 'output-metadata.json') | ConvertFrom-Json
    if ($apkMetadata.elements.Count -ne 1) { throw 'Expected one universal full debug APK.' }
    $sourceApk = Join-Path $apkDirectory $apkMetadata.elements[0].outputFile
    $outputDir = Join-Path $PSScriptRoot 'build\standalone'
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    $outputApk = Join-Path $outputDir 'TravelCard-0.11-debug.apk'
    Copy-Item -LiteralPath $sourceApk -Destination $outputApk -Force
    Write-Output "APK: $outputApk"
    if ($Install) {
        $adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
        & $adb -s $Serial install -r $outputApk
        if ($LASTEXITCODE -ne 0) { throw 'APK installation failed.' }
        & $adb -s $Serial shell am start -W -n 'com.vsmartcard.acardemulator.standalone.debug/com.vsmartcard.acardemulator.MainActivity'
        if ($LASTEXITCODE -ne 0) { throw 'Could not launch the main activity.' }
    }
} finally {
    Pop-Location
    $env:JAVA_HOME = $savedJava
    $env:ANDROID_HOME = $savedAndroid
    $env:ANDROID_SDK_ROOT = $savedSdk
}
