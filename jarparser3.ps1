<#
.SYNOPSIS
  Analyze Minecraft-related Prefetch files (after last boot) for imports/signatures.
.DESCRIPTION
  Only analyzes Prefetch files and imports related to Minecraft.
#>

param(
  [switch]$ExportCSV,
  [string]$CsvPath = "$env:TEMP\MinecraftPFReport.csv"
)

function Write-Header {
  $art = @"
╔══════════════════════════════════════════════════════╗
║     MINECRAFT PREFETCH ANALYZER - by Copilot        ║
╚══════════════════════════════════════════════════════╝
"@
  Write-Host $art -ForegroundColor Green
  Write-Host "`nAnalyzing Prefetch files ONLY for Minecraft activity.`n" -ForegroundColor Yellow
}

function Download-PECmd {
  param([string]$Url, [string]$Path)
  if (-not (Test-Path $Path)) {
    Write-Host "Downloading PECmd.exe..." -ForegroundColor Green
    try {
      Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing
      if (-not (Test-Path $Path)) { throw "Download failed." }
    } catch {
      Write-Host "Failed to download PECmd.exe: $_" -ForegroundColor Red
      exit 1
    }
  }
}

function Get-MinecraftPrefetchFiles {
  param([datetime]$Since)
  $dir = "C:\Windows\Prefetch"
  if (-not (Test-Path $dir)) {
    Write-Host "Prefetch directory not found!" -ForegroundColor Red
    exit 1
  }
  $mcPf = Get-ChildItem $dir -Filter "MINECRAFTLAUNCHER.EXE-*.pf" | Where-Object { $_.LastWriteTime -gt $Since }
  $javaPf = Get-ChildItem $dir -Filter "JAVA*.EXE-*.pf" | Where-Object { $_.LastWriteTime -gt $Since }
  # Only keep java/javaw files likely related to Minecraft (.minecraft in command line or import)
  return $mcPf + $javaPf
}

function Parse-Imports {
  param([string[]]$Lines)
  $importLines = $Lines | Where-Object { $_ -match '\\VOLUME|:\\\\' }
  $importLines | ForEach-Object {
    $fixed = $_ -replace '\\VOLUME{[^}]+}', 'C:'
    $fixed = $fixed -replace '^\d+: ', ''
    $fixed.Trim()
  }
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
  $files = Get-MinecraftPrefetchFiles -Since $boot

  if (-not $files) {
    Write-Host "No recent Minecraft Prefetch files found." -ForegroundColor Red
    Remove-Item $pecmdPath -ErrorAction SilentlyContinue
    return
  }

  $results = @()

  foreach ($pf in $files) {
    Write-Host "`nAnalyzing $($pf.Name) (LastWrite: $($pf.LastWriteTime))..." -ForegroundColor Cyan
    try {
      $out = & $pecmdPath -f $pf.FullName
    } catch {
      Write-Host "PECmd execution failed: $_" -ForegroundColor Red
      continue
    }
    $imports = Parse-Imports -Lines $out
    # Only keep lines that reference .minecraft (case-insensitive)
    $mcImports = $imports | Where-Object { $_.ToLower() -like "*\.minecraft*" }
    if (-not $mcImports) {
      Write-Host "  No Minecraft-related imports found." -ForegroundColor Yellow
      continue
    }
    foreach ($imp in $mcImports) {
      if ($imp -notmatch '\\[^\\]+\.[^\\]+$') { continue }
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
        ImportPath = $imp
        Signature  = $msg
      }
    }
  }

  if ($results.Count -eq 0) {
    Write-Host "`nNo Minecraft imports found after boot." -ForegroundColor Yellow
  } else {
    Write-Host "`nSummary Table:`n" -ForegroundColor Cyan
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
