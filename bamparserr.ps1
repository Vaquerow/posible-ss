<#
.SYNOPSIS
    BAM Parser - Windows Executed Programs Analyzer

.DESCRIPTION
    Parses the BAM registry to list executed programs by user, execution time, and other metadata.
    Supports output to Out-GridView, Table, or CSV.
    Optionally checks digital signatures.

.PARAMETER NoSignature
    Skip digital signature verification for faster execution.

.PARAMETER Csv
    Export results to a CSV file.

.PARAMETER CsvPath
    Specify the path for the CSV export.

.EXAMPLE
    .\bamparser.ps1 -NoSignature

.NOTES
    Requires administrative privileges.
    PowerShell 5.1+ recommended.
#>

[CmdletBinding()]
param(
    [switch]$NoSignature,
    [switch]$Csv,
    [string]$CsvPath = ".\bam_entries.csv"
)

function Show-Banner {
    Write-Host -ForegroundColor Cyan @"
 ____  ___    __  ___    ____  ____   __    ___  ____  ____ 
(  _ \(  ,)  /  \(  ,)  (  _ \(  _ \ /  \  / __)(  _ \(  _ \
 ) _ < )  \ (  O ))  \   ) __/ )   /(  O )( (__  )   / )   /
(____/(_)\_) \__/(_)\_) (__)  (__\_) \__/  \___)(__\_)(__\_)
"@
    Write-Host ""
    Write-Host -ForegroundColor Yellow "BAM Parser - Windows Executed Programs Analyzer"
    Write-Host ""
}

function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-DriveMappings {
    # Maps NT device paths to drive letters, e.g. \Device\HarddiskVolume2 -> D:
    $volumes = Get-CimInstance -ClassName Win32_Volume | Where-Object { $_.DriveLetter }
    $map = @{}
    foreach ($v in $volumes) {
        $device = $v.DeviceID.TrimEnd('\')
        $map[$device] = $v.DriveLetter
    }
    return $map
}

function Convert-DevicePathToDrivePath {
    param([string]$DevicePath, [hashtable]$DriveMap)
    foreach ($dev in $DriveMap.Keys) {
        if ($DevicePath -like "$dev*") {
            $relPath = $DevicePath.Substring($dev.Length)
            $relPath = $relPath -replace '\\', '\'
            return "$($DriveMap[$dev])$relPath"
        }
    }
    return $DevicePath
}

function Get-DigitalSignatureStatus {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath -PathType Leaf)) { return "File not found" }
    try {
        $status = (Get-AuthenticodeSignature -FilePath $FilePath).Status
    } catch {
        return "Signature check error"
    }
    switch ($status) {
        'Valid'        { return 'Valid' }
        'NotSigned'    { return 'Not signed' }
        'HashMismatch' { return 'Invalid (HashMismatch)' }
        'NotTrusted'   { return 'Invalid (Not trusted)' }
        default        { return "Invalid ($status)" }
    }
}

function Get-BamUsers {
    $roots = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\',
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\'
    )
    $users = @()
    foreach ($root in $roots) {
        if (Test-Path $root) {
            $users += Get-ChildItem -Path $root | Select-Object -ExpandProperty PSChildName
        }
    }
    return $users | Sort-Object -Unique
}

function Get-BamEntries {
    param(
        [hashtable]$DriveMap,
        [bool]$CheckSig = $true
    )
    $users = Get-BamUsers
    $roots = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\',
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\'
    )
    # Get timezone bias in minutes
    $tz = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
    $userBias = $tz.ActiveTimeBias

    $entries = @()
    foreach ($sid in $users) {
        foreach ($root in $roots) {
            $userKey = "${root}$sid"
            if (-not (Test-Path $userKey)) { continue }
            try {
                $user = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
            } catch { $user = 'Unknown' }
            $props = (Get-Item -Path $userKey).Property
            $propValues = Get-ItemProperty -Path $userKey
            foreach ($prop in $props) {
                $value = $propValues.$prop
                if ($value -is [byte[]] -and $value.Length -eq 24) {
                    # Parse FILETIME from bytes 8-1 (little endian)
                    $hex = [System.BitConverter]::ToString($value[7..0]) -replace '-',''
                    $dtUtc = [DateTime]::FromFileTimeUtc([Convert]::ToInt64($hex,16))
                    $localTime = $dtUtc.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                    $userTime = ($dtUtc).AddMinutes(-1 * $userBias).ToString('yyyy-MM-dd HH:mm:ss')
                    $filePath = Convert-DevicePathToDrivePath -DevicePath $prop -DriveMap $DriveMap
                    $appName = Split-Path -Leaf $filePath
                    $signature = if ($CheckSig) { Get-DigitalSignatureStatus -FilePath $filePath } else { "Skipped" }

                    $entries += [PSCustomObject]@{
                        'Examined Time (Local)'      = $localTime
                        'Last Execution (User Time)' = $userTime
                        'Application'                = $appName
                        'File Path'                  = $filePath
                        'Digital Signature'          = $signature
                        'User'                       = $user
                        'SID'                        = $sid
                        'Registry Root'              = $root
                    }
                }
            }
        }
    }
    return $entries
}

# MAIN SCRIPT

Clear-Host
Show-Banner

if (-not (Test-Admin)) {
    Write-Warning "Please run this script as Administrator."
    Start-Sleep -Seconds 5
    exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()
$driveMap = Get-DriveMappings
$bamEntries = Get-BamEntries -DriveMap $driveMap -CheckSig:(!$NoSignature)

if (-not $bamEntries -or $bamEntries.Count -eq 0) {
    Write-Host "No BAM entries found or insufficient permissions." -ForegroundColor Red
    exit
}

if ($Csv) {
    try {
        $bamEntries | Export-Csv -Path $CsvPath -NoTypeInformation
        Write-Host "Exported to $CsvPath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to export CSV: $_" -ForegroundColor Red
    }
} elseif (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
    $bamEntries | Out-GridView -Title "BAM Executed Programs"
} else {
    $bamEntries | Format-Table -AutoSize
}

$sw.Stop()
Write-Host "`n✔ Completed in $([math]::Round($sw.Elapsed.TotalSeconds,2)) seconds." -ForegroundColor Green
