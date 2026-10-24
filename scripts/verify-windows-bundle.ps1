param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("x64", "arm64")]
  [string]$Arch
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Target = if ($Arch -eq "x64") { "x86_64-pc-windows-msvc" } else { "aarch64-pc-windows-msvc" }
$Machine = if ($Arch -eq "x64") { "x64" } else { "arm64" }
$Exe = Join-Path "src-tauri/target/$Target/release" "wedima-vpn-wg.exe"
if (-not (Test-Path $Exe)) { throw "Missing $Exe" }

$Proc = Start-Process -FilePath $Exe -ArgumentList "--version" -Wait -PassThru -WindowStyle Hidden
if ($Proc.ExitCode -ne 0) { throw "Windows smoke test exited $($Proc.ExitCode)" }

$Nsis = Get-ChildItem "src-tauri/target/$Target/release/bundle/nsis/*.exe" | Select-Object -First 1
$Msi = Get-ChildItem "src-tauri/target/$Target/release/bundle/msi/*.msi" | Select-Object -First 1
if (-not $Nsis -or -not $Msi) { throw "NSIS or MSI installer was not produced" }

node scripts/verify-artifact.mjs --kind pe --machine $Machine $Nsis.FullName
node scripts/verify-artifact.mjs --kind msi $Msi.FullName

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
  node scripts/verify-artifact.mjs --kind sig $Sig.FullName
} else {
  Write-Host "::warning::TAURI_SIGNING_PRIVATE_KEY is not set. Updater metadata will not be published."
}
