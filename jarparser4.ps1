<#
.SYNOPSIS
  Detects Minecraft-related java/javaw launches after last boot by analyzing Prefetch, focusing on suspicious mods/hacks.
#>

param(
  [switch]$ExportCSV,
  [string]$CsvPath = "$env:TEMP\MinecraftHackCheck.csv"
)

function Write-Header {
  $art = @"
╔══════════════════════════════════════════════════════╗
║   MINECRAFT JAVA EXECUTION HACK FINDER (by Copilot) ║
╚══════════════════════════════════════════════════════╝
"@
  Write-Host $art -ForegroundColor Green
  Write-Host "`nScanning for java/javaw launches of Minecraft after last boot.`n" -ForegroundColor Yellow
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

function IsMinecraftLaunch {
  param([string[]]$Lines)
  # Tries to detect .minecraft in command line or imports
  $text = $Lines -join "`n"
  return $text.ToLower().Contains("\.minecraft") -or $text.ToLower().Contains('/.minecraft')
}

function IsSuspiciousPath {
  param([string]$Path)
  $low = $Path.ToLower()
  # Add more folders as needed
  return ($low -match '\\\.minecraft(\\|/)(mods|hacks|cheat|injected|impact|liquid|worst|aristois|future|rusher|jigsaw|salhack|lambda|meteor|kami|gamesense|wurst|sodium|baritone|toolbox|utility|client)') `
    -or ($low -match '\\\.minecraft(\\|/)versions\\[^\\]+(hack|cheat|inject|mod)')
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
    $imports = Parse-PECmd $out
    $mcImports = $imports | Where-Object { $_.ToLower() -like "*\.minecraft*" }
    $suspects = $mcImports | Where-Object { IsSuspiciousPath $_ }
    if (-not $suspects) {
      Write-Host "  No suspicious mods/hacks found in .minecraft." -ForegroundColor Yellow
      continue
    }
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
        SuspectPath= $imp
        Signature  = $msg
      }
    }
  }

  if ($results.Count -eq 0) {
    Write-Host "`nNo suspicious Minecraft-related hacks/mods found after boot." -ForegroundColor Yellow
  } else {
    Write-Host "`nSuspicious files detected (possible hacks/mods):`n" -ForegroundColor Magenta
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
