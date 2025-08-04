<#
.SYNOPSIS
  Checks Prefetch files for java/javaw after the last boot, analyzes imports, checks digital signatures, and displays interactive, colorful results.
#>

[CmdletBinding()]
param(
    [switch]$ExportCSV,
    [string]$CsvOutput = "$env:TEMP\JavaPfAnalysis.csv"
)

function Show-Intro {
    $banner = @"
╔════════════════════════════════════════════════════════════╗
║  🔍  JAVA PREFETCH & IMPORT ANALYZER (by GitHub Copilot)  ║
╚════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host " " 
    Write-Host "   🚀 Scanning for post-boot java/javaw Prefetch files..." -ForegroundColor Yellow
    Write-Host " "
}

function Download-PECmd {
    param([string]$Url, [string]$OutPath)
    if (-not (Test-Path $OutPath)) {
        Write-Host "📦 Downloading PECmd.exe..." -ForegroundColor Green
        try {
            Invoke-WebRequest -Uri $Url -OutFile $OutPath -UseBasicParsing
            Write-Host "✔️ Download complete." -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to download PECmd.exe: $_" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "PECmd.exe already present in $OutPath." -ForegroundColor Gray
    }
}

function Get-JavaPrefetchFiles {
    param([datetime]$Since)
    $folder = "C:\Windows\Prefetch"
    Write-Host "⏳ Searching Prefetch for java/javaw files since $Since..." -ForegroundColor Magenta
    Get-ChildItem -Path $folder -Filter *.pf -ErrorAction SilentlyContinue | 
        Where-Object { 
            ($_.Name -match 'java(\.exe|w)?\_.*\.pf$') -and 
            ($_.LastWriteTime -gt $Since)
        } | 
        Sort-Object LastWriteTime -Descending
}

function Parse-PECmdOutput {
    param([string[]]$OutputLines)
    # Parses lines that look like imports or file references
    return $OutputLines | Where-Object { $_ -match '\\VOLUME|:\\\\' }
}

function Replace-VolumePaths {
    param([string]$Path)
    # Replace \VOLUME{...} with C: and clean up
    $line = $Path -replace '\\VOLUME{.*?}', 'C:'
    $line = $line -replace '^\d+: ', ''
    return $line.Trim()
}

function Analyze-Imports {
    param([string[]]$Imports)
    $results = @()
    foreach ($raw in $Imports) {
        $line = Replace-VolumePaths $raw
        if ($line -match '\\[^\\]+\.[^\\]+$') {
            $exists = Test-Path $line
            $signature = $null
            if ($exists) {
                $sigObj = Get-AuthenticodeSignature -FilePath $line -ErrorAction SilentlyContinue
                $signature = $sigObj.Status
            }
            $results += [PSCustomObject]@{
                Path      = $line
                Exists    = $exists
                Signature = $signature
            }
        }
    }
    return $results
}

function Show-Results {
    param([string]$PfName, [datetime]$PfTime, [PSObject[]]$Results)
    Write-Host ""
    Write-Host "═════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "📂 File: $PfName" -ForegroundColor White
    Write-Host "🕓 Last Modified: $PfTime" -ForegroundColor White

    if ($Results.Count -eq 0) {
        Write-Host "❗ No relevant imports found." -ForegroundColor Red
    } else {
        Write-Host "📦 Imports:" -ForegroundColor Yellow
        foreach ($r in $Results) {
            if (-not $r.Exists) {
                Write-Host "   [NO EXISTE] $($r.Path)" -ForegroundColor DarkGray
            } elseif ($r.Signature -ne 'Valid') {
                Write-Host "   [SIN FIRMA] $($r.Path)" -ForegroundColor Red
            } else {
                Write-Host "   [OK] $($r.Path)" -ForegroundColor Green
            }
        }
    }
    Write-Host "═════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

# MAIN FLOW

Clear-Host
Show-Intro

# Download PECmd if needed
$pecmdUrl = "https://github.com/NoDiff-del/JARs/releases/download/Jar/PECmd.exe"
$pecmdPath = "$env:TEMP\PECmd.exe"
Download-PECmd -Url $pecmdUrl -OutPath $pecmdPath

$logonTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
$files = Get-JavaPrefetchFiles -Since $logonTime

if (-not $files -or $files.Count -eq 0) {
    Write-Host "😢 No Prefetch files for java/javaw.exe found after last boot." -ForegroundColor Red
    exit 0
}

$total = $files.Count
$summary = @()

$idx = 0
foreach ($pf in $files) {
    $idx++
    Write-Progress -Activity "Analyzing Prefetch" -Status "$($pf.Name)" -PercentComplete (($idx/$total)*100)
    try {
        $pecmdOutput = & $pecmdPath -f $pf.FullName
    } catch {
        Write-Host "⚠️ Error running PECmd on $($pf.Name): $_" -ForegroundColor Red
        continue
    }
    $imports = Parse-PECmdOutput -OutputLines $pecmdOutput
    $analysis = Analyze-Imports -Imports $imports
    Show-Results -PfName $pf.Name -PfTime $pf.LastWriteTime -Results $analysis

    foreach ($row in $analysis) {
        $summary += [PSCustomObject]@{
            PrefetchFile = $pf.Name
            LastWrite    = $pf.LastWriteTime
            ImportPath   = $row.Path
            Exists       = $row.Exists
            Signature    = $row.Signature
        }
    }
}

Write-Host ""
Write-Host "═════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "🎉 SUMMARY:" -ForegroundColor Magenta
Write-Host "    Total Prefetch analyzed: $total" -ForegroundColor Yellow
Write-Host "    Total imports found: $($summary.Count)" -ForegroundColor Yellow
Write-Host "═════════════════════════════════════════════════════════" -ForegroundColor Cyan

if ($ExportCSV -and $summary.Count -gt 0) {
    $summary | Export-Csv -Path $CsvOutput -NoTypeInformation
    Write-Host "📄 Exported analysis to $CsvOutput" -ForegroundColor Green
}

# Clean up temp PECmd
if (Test-Path $pecmdPath) {
    Remove-Item $pecmdPath -Force
    Write-Host "🧹 Temp file PECmd.exe removed." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "✅ Done! Press Enter to exit." -ForegroundColor Green
Read-Host
