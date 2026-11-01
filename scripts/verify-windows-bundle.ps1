param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("x64", "arm64")]
  [string]$Arch
)
$ErrorActionPreference = "Stop"
# pwsh does not stop the script when node exits non-zero unless this is set.
# The previous NSIS check printed "PE machine is 0x14c" and the job still passed.
$PSNativeCommandUseErrorActionPreference = $true
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Target = if ($Arch -eq "x64") { "x86_64-pc-windows-msvc" } else { "aarch64-pc-windows-msvc" }
$Machine = if ($Arch -eq "x64") { "x64" } else { "arm64" }
$Exe = Join-Path "src-tauri/target/$Target/release" "wedima-vpn-wg.exe"
if (-not (Test-Path $Exe)) { throw "Missing $Exe" }

function Invoke-NodeCheck {
  param([Parameter(Mandatory = $true)][string[]]$ArgumentList)
  & node @ArgumentList
  if ($LASTEXITCODE -ne 0) {
    throw "node $($ArgumentList -join ' ') exited $LASTEXITCODE"
  }
}

$Proc = Start-Process -FilePath $Exe -ArgumentList "--version" -Wait -PassThru -WindowStyle Hidden
if ($Proc.ExitCode -ne 0) { throw "Windows smoke test exited $($Proc.ExitCode)" }

$Nsis = Get-ChildItem "src-tauri/target/$Target/release/bundle/nsis/*.exe" | Select-Object -First 1
$Msi = Get-ChildItem "src-tauri/target/$Target/release/bundle/msi/*.msi" | Select-Object -First 1
if (-not $Nsis -or -not $Msi) { throw "NSIS or MSI installer was not produced" }

# The app executable must be the target machine. A 32-bit file here fails the job.
Invoke-NodeCheck @(
  "scripts/verify-artifact.mjs", "--kind", "pe", "--machine", $Machine, $Exe
)

# NSIS ships a 32-bit stub (0x14c). Accept that only after the app exe matched.
Invoke-NodeCheck @(
  "scripts/verify-artifact.mjs", "--kind", "pe", "--machine", $Machine,
  "--allow-i386-stub", $Nsis.FullName
)
Invoke-NodeCheck @(
  "scripts/verify-artifact.mjs", "--kind", "msi", $Msi.FullName
)

$Dll = Join-Path "src-tauri/target/$Target/release" "wintun.dll"
if (-not (Test-Path $Dll)) { throw "wintun.dll was not staged beside the executable" }

if ($env:WINDOWS_CERTIFICATE) {
  $SignTool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe |
    Sort-Object FullName -Descending |
    Select-Object -First 1
  if (-not $SignTool) { throw "signtool.exe was not found" }
  & $SignTool.FullName verify /pa $Nsis.FullName
  if ($LASTEXITCODE -ne 0) { throw "signtool verify failed" }
} else {
  Write-Host "::warning::WINDOWS_CERTIFICATE is not set. The installer is structurally valid but unsigned."
}

if ($env:TAURI_SIGNING_PRIVATE_KEY) {
  $Sig = Get-ChildItem "src-tauri/target/$Target/release/bundle/nsis/*.exe.sig" | Select-Object -First 1
  if (-not $Sig) { throw "Updater signature is missing" }
  Invoke-NodeCheck @(
    "scripts/verify-artifact.mjs", "--kind", "sig", $Sig.FullName
  )
} else {
  Write-Host "::warning::TAURI_SIGNING_PRIVATE_KEY is not set. Updater metadata will not be published."
}
