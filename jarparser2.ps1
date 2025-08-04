<#
.SYNOPSIS
  Analyze java/javaw Prefetch files (after last boot) for import anomalies and signatures.
.DESCRIPTION
  Downloads PECmd if missing, checks for Prefetch files for java/javaw, parses imports, checks signatures, and summarizes.
  Run from an Administrator PowerShell window.
#>

param(
  [switch]$ExportCSV,
  [string]$CsvPath = "$env:TEMP\JavaPFReport.csv"
)

function Write-Header {
  $art = @"
╔════════════════════════════════════════════════════╗
║    JAVA PREFETCH ANALYZER - by GitHub Copilot     ║
╚════════════════════════════════════════════════════╝
"@
  Write-Host $art -ForegroundColor Cyan
  Write-Host "`nThis script scans Prefetch for java/javaw post-boot, checks imports & signatures.`n" -ForegroundColor Yellow
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

function Get-PrefetchFiles {
  param([datetime]$Since)
  $dir = "C:\Windows\Prefetch"
  if (-not (Test-Path $dir)) {
    Write-Host "Prefetch directory not found!" -ForegroundColor Red
    exit 1
  }
  Get-ChildItem $dir -Filter *.pf | Where-Object {
    ($_.Name -match '^JAVA(W)?\.EXE') -and ($_.LastWriteTime -gt $Since)
  } | Sort-Object LastWriteTime -Descending
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
  $files = Get-PrefetchFiles -Since $boot

  if (-not $files) {
    Write-Host "No recent java/javaw Prefetch files found." -ForegroundColor Red
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
    if (-not $imports) {
      Write-Host "  No imports found." -ForegroundColor Yellow
      continue
    }
    foreach ($imp in $imports) {
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
    Write-Host "`nNo signed/unsigned java/javaw imports found after boot." -ForegroundColor Yellow
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
