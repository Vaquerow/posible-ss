<#
.SYNOPSIS
  Detects Minecraft hacked clients or mods by analyzing Java Prefetch launches after last boot.
.DESCRIPTION
  Looks for java/javaw Prefetch launches of Minecraft and scans for suspicious mods/clients.
#>

param(
  [switch]$ExportCSV,
  [string]$CsvPath = "$env:TEMP\MinecraftHackReport.csv"
)

# List of common hacked client/mod names (expand as needed)
$hackNames = @(
  'wurst', 'aristois', 'jigsaw', 'impact', 'future', 'liquidbounce', 'meteor',
  'kami', 'gamesense', 'salhack', 'lambda', 'rusherhack', 'baritone', 'toolbox',
  'bypass', 'utility', 'inject', 'injected', 'hack', 'cheat', 'client'
)

function Write-Header {
  $art = @"
╔══════════════════════════════════════════════════════╗
║   MINECRAFT HACKED CLIENT DETECTOR                   ║
╚══════════════════════════════════════════════════════╝
"@
  Write-Host $art -ForegroundColor Green
  Write-Host "`nScanning for Java-launched Minecraft with suspicious mods/clients after last boot.`n" -ForegroundColor Yellow
}

function Download-PECmd {
  param([string]$Url, [string]$Path)
  if (-not (Test-Path $Path)) {
    Write-Host "Downloading PECmd.exe..." -ForegroundColor Green
    try {
      Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing
    } catch {
      Write-Host "Failed to download PECmd.exe: $_" -ForegroundColor Red
      exit 1
    }
  }
}

function Get-MinecraftJavaPrefetch {
  param([datetime]$Since)
  $dir = "C:\Windows\Prefetch"
  Get-ChildItem $dir -Filter "JAVA*.EXE-*.pf" | Where-Object { $_.LastWriteTime -gt $Since }
}

function Parse-PECmd {
  param([string[]]$Lines)
  $lines = $Lines | Where-Object { $_ -match '\\VOLUME|:\\\\' }
  $lines | ForEach-Object {
    $_ -replace '\\VOLUME{[^}]+}', 'C:' -replace '^\d+: ', '' | ForEach-Object { $_.Trim() }
  }
}

function Get-CommandLine {
  param([string[]]$Lines)
  # Try to extract command line from PECmd output
  $cmd = $Lines | Where-Object { $_ -match 'CommandLine\s*:' }
  if ($cmd) {
    return ($cmd -replace '.*CommandLine\s*:\s*', '').Trim()
  }
  return ""
}

function IsMinecraftLaunch {
  param([string[]]$Lines)
  $text = $Lines -join "`n"
  return $text.ToLower().Contains("\.minecraft") -or $text.ToLower().Contains('/.minecraft')
}

function IsSuspectModOrClient {
  param([string]$Path)
  $low = $Path.ToLower()
  foreach ($hack in $hackNames) {
    if ($low -match $hack) { return $true }
  }
  return $false
}

function Check-Signature {
  param($Path)
  if (-not (Test-Path $Path)) { return "NOFILE" }
  try {
    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
    return $sig.Status
  } catch { return "ERROR" }
}

function Main {
  Write-Header
  $pecmdUrl = "https://github.com/NoDiff-del/JARs/releases/download/Jar/PECmd.exe"
  $pecmdPath = "$env:TEMP\PECmd.exe"
  Download-PECmd -Url $pecmdUrl -Path $pecmdPath

  $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
  $files = Get-MinecraftJavaPrefetch -Since $boot

  if (-not $files) {
    Write-Host "No recent java/javaw Prefetch files found." -ForegroundColor Red
    Remove-Item $pecmdPath -ErrorAction SilentlyContinue
    return
  }

  $results = @()
  foreach ($pf in $files) {
    Write-Host "`nAnalyzing $($pf.Name) (LastWrite: $($pf.LastWriteTime))..." -ForegroundColor Cyan
    $out = & $pecmdPath -f $pf.FullName
    if (-not (IsMinecraftLaunch $out)) {
      Write-Host "  Not a Minecraft launch, skipping." -ForegroundColor Gray
      continue
    }
    $cmdline = Get-CommandLine $out
    $imports = Parse-PECmd $out
    $mcImports = $imports | Where-Object { $_.ToLower() -like "*\.minecraft*" }
    $suspects = $mcImports | Where-Object { IsSuspectModOrClient $_ }
    if (-not $suspects) {
      Write-Host "  No known hacked client/mod detected in this launch." -ForegroundColor Yellow
      continue
    }
    Write-Host "  Command line: $cmdline" -ForegroundColor DarkYellow
    foreach ($imp in $suspects) {
      $sig = Check-Signature $imp
      switch ($sig) {
        'Valid' { $color = 'Green'; $msg = 'SIGNED' }
        'NotSigned' { $color = 'Red'; $msg = 'UNSIGNED' }
        'NOFILE' { $color = 'DarkGray'; $msg = 'NOFILE' }
        default { $color = 'DarkYellow'; $msg = $sig }
      }
      Write-Host "  [$msg] $imp" -ForegroundColor $color
      $results += [PSCustomObject]@{
        Prefetch   = $pf.Name
        LastWrite  = $pf.LastWriteTime
        CommandLine= $cmdline
        SuspectMod = $imp
        Signature  = $msg
      }
    }
  }

  if ($results.Count -eq 0) {
    Write-Host "`nNo Minecraft hacked clients/mods detected after boot." -ForegroundColor Yellow
  } else {
    Write-Host "`nSuspicious hacked clients/mods detected:`n" -ForegroundColor Magenta
    $results | Format-Table -AutoSize
    if ($ExportCSV) {
      $results | Export-Csv -Path $CsvPath -NoTypeInformation
      Write-Host "`nResults exported to $CsvPath" -ForegroundColor Green
    }
  }

  if (Test-Path $pecmdPath) { Remove-Item $pecmdPath -Force }
  Write-Host "`nDone! Press Enter to exit." -ForegroundColor Magenta
  Read-Host
}

Main
