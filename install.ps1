<#
.SYNOPSIS
  Transit Community Edition — Windows installer.

    irm https://raw.githubusercontent.com/transit-community/transit/main/install.ps1 | iex

  Downloads the newest release's setup.exe from GitHub, verifies its SHA-256
  against the published SHA256SUMS.txt, removes the mark-of-the-web only
  after that check passes, and runs the installer silently for the current
  user (no administrator rights needed). Re-running updates in place.

  The build is not code-signed, so SmartScreen would otherwise warn on
  launch; the checksum is the integrity check that stands in for a
  signature. It is not independent provenance: checksum and installer come
  from the same GitHub release over the same TLS.

.PARAMETER Version
  Install a specific version (default: newest release).
.PARAMETER Yes
  Do not ask for confirmation.
.PARAMETER DryRun
  Download and verify, but do not install.
#>
[CmdletBinding()]
param(
  [string]$Version = "",
  [switch]$Yes,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$Repo = if ($env:TRANSIT_REPO) { $env:TRANSIT_REPO } else { "transit-community/transit" }
$Api = "https://api.github.com/repos/$Repo"
$Dl = "https://github.com/$Repo/releases/download"

function Die($msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($arch -ne "X64") { Die "unsupported architecture: $arch. Transit Community Edition publishes x64 Windows builds only." }

if (-not $Version) {
  try { $rel = Invoke-RestMethod -Uri "$Api/releases/latest" -Headers @{ "User-Agent" = "transit-community-installer" } }
  catch { Die "could not reach the GitHub release API: $($_.Exception.Message)" }
  $Version = $rel.tag_name -replace '^v', ''
}

try { $sums = (Invoke-WebRequest -Uri "$Dl/v$Version/SHA256SUMS.txt" -UseBasicParsing).Content }
catch { Die "no published release v$Version (or it has no SHA256SUMS.txt)." }

$line = ($sums -split "`n") | Where-Object { $_ -match '_x64-setup\.exe\s*$' } | Select-Object -First 1
if (-not $line) { Die "release v$Version publishes no x64 setup.exe." }
$sha = ($line -split '\s+', 2)[0].ToLowerInvariant()
$file = ($line -replace '^[0-9A-Fa-f]+\s+', '').Trim()
$asset = $file -replace ' ', '.'
$url = "$Dl/v$Version/$asset"

# Already installed? The NSIS installer registers under the app's uninstall key.
$current = $null
foreach ($hive in @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")) {
  $k = Get-ItemProperty $hive -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq "Transit Community Edition" } | Select-Object -First 1
  if ($k) { $current = $k.DisplayVersion; break }
}
$action = if (-not $current) { "install" } elseif ($current -eq $Version) { "reinstall" } else { "update (currently $current)" }

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("transit-install-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
$dest = Join-Path $work $asset

Write-Host ""
Write-Host "Transit Community Edition $Version — Windows installer" -ForegroundColor White
Write-Host ""
Write-Host ("  {0,-10} {1}" -f "Detected", "Windows $([System.Environment]::OSVersion.Version) ($arch)")
Write-Host ("  {0,-10} {1}" -f "Action", $action)
Write-Host ("  {0,-10} {1}" -f "Method", "download the setup.exe, verify SHA-256, run it silently for the current user")
Write-Host ("  {0,-10} {1}" -f "Source", $url)
Write-Host ("  {0,-10} {1}" -f "sha256", $sha)
Write-Host ""
Write-Host "Will run:"
Write-Host "  `"$dest`" /S"
Write-Host ""

if (-not $Yes) {
  if (-not [Environment]::UserInteractive) { Die "no interactive session to confirm. Re-run with -Yes to proceed unattended." }
  $reply = Read-Host "Continue? [y/N]"
  if ($reply -notmatch '^(y|yes)$') { Write-Host "Cancelled."; exit 1 }
  Write-Host ""
}

Write-Host "Downloading $asset ..."
try { Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing }
catch { Die "download failed: $($_.Exception.Message)" }
$got = (Get-FileHash -Path $dest -Algorithm SHA256).Hash.ToLowerInvariant()
if ($got -ne $sha) { Remove-Item -Force $dest; Die "checksum mismatch — the download does not match the published sha256. Not installing." }
Write-Host "Checksum OK."
if ($DryRun) { Write-Host "-DryRun: verified $asset, stopping before install."; Remove-Item -Recurse -Force $work; exit 0 }

# Only after the checksum matched: drop the mark-of-the-web so the silent run is not blocked.
Unblock-File -Path $dest
$p = Start-Process -FilePath $dest -ArgumentList "/S" -Wait -PassThru
Remove-Item -Recurse -Force $work
if ($p.ExitCode -ne 0) { Die "the installer exited with code $($p.ExitCode)." }

Write-Host ""
Write-Host "Transit Community Edition $Version installed." -ForegroundColor White
Write-Host "Launch it from the Start menu. Update later by re-running this installer."
