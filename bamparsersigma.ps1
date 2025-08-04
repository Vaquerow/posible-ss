<#
.SYNOPSIS
    BAM Analyzer: First and Last Execution per Program and User
.DESCRIPTION
    Scans the BAM registry and shows for each program/user the first and last time it was executed.
    Multi-drive and digital signature support.
.NOTES
    Run as Administrator.
#>

[CmdletBinding()]
param(
    [switch]$ExportCSV,
    [string]$CsvPath = "$env:TEMP\\BAM_Report.csv"
)

function Show-Banner {
    $banner = @"
ââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
â                 BAM ANALYZER - PowerShell            â
ââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
}

function Test-Admin {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-DriveMappings {
    $mappings = @{}
    Get-CimInstance -ClassName Win32_Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
        $device = $_.DeviceID.TrimEnd('\')
        $mappings[$device] = $_.DriveLetter
    }
    return $mappings
}

function Convert-DevicePathToDrive {
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

function Get-SignatureStatus {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath -PathType Leaf)) {
        return "No disponible"
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath
        switch ($sig.Status) {
            'Valid'        { return 'Firma vÃ¡lida' }
            'NotSigned'    { return 'No estÃ¡ firmado' }
            'HashMismatch' { return 'Firma invÃ¡lida (HashMismatch)' }
            'NotTrusted'   { return 'Firma invÃ¡lida (No confiable)' }
            default        { return "Firma invÃ¡lida ($($sig.Status))" }
        }
    } catch {
        return "Error de firma"
    }
}

function Get-BamUsers {
    $roots = @('bam', 'bam\State')
    $users = @()
    foreach ($p in $roots) {
        $key = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$p\\UserSettings\\"
        if (Test-Path $key) {
            $users += Get-ChildItem -Path $key | Select-Object -ExpandProperty PSChildName
        }
    }
    return $users | Sort-Object -Unique
}

function Get-BamEntries {
    param([hashtable]$DriveMap)
    $users = Get-BamUsers
    $registryRoots = @(
        'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bam\\',
        'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bam\\state\\'
    )
    $tz = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation'
    $userBias = $tz.ActiveTimeBias

    $entries = @()
    foreach ($sid in $users) {
        foreach ($root in $registryRoots) {
            $key = "${root}UserSettings\\$sid"
            if (-not (Test-Path $key)) { continue }
            try {
                $user = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
            } catch { $user = 'Desconocido' }
            $props = (Get-Item -Path $key).Property
            $propValues = Get-ItemProperty -Path $key
            foreach ($prop in $props) {
                $value = $propValues.$prop
                if ($value -is [byte[]] -and $value.Length -eq 24) {
                    $hex = [System.BitConverter]::ToString($value[7..0]) -replace '-',''
                    $dtUtc = [DateTime]::FromFileTimeUtc([Convert]::ToInt64($hex,16))
                    $localTime = $dtUtc.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')

                    $filePath = Convert-DevicePathToDrive -DevicePath $prop -DriveMap $DriveMap
                    $appName = Split-Path -Leaf $filePath
                    $signature = Get-SignatureStatus -FilePath $filePath

                    $entries += [PSCustomObject]@{
                        'Usuario'             = $user
                        'Hora ejecuciÃ³n UTC'  = $dtUtc
                        'Hora ejecuciÃ³n local'= $localTime
                        'AplicaciÃ³n'          = $appName
                        'Ruta del archivo'    = $filePath
                        'Firma digital'       = $signature

                    }
                }
            }
        }
    }
    return $entries
}

# MAIN

Clear-Host
Show-Banner

if (-not (Test-Admin)) {
    Write-Warning 'Ejecute el script como Administrador.'
    Start-Sleep -Seconds 5
    exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()
$driveMap = Get-DriveMappings
$bamEntries = Get-BamEntries -DriveMap $driveMap

if (-not $bamEntries -or $bamEntries.Count -eq 0) {
    Write-Host "No se encontraron entradas BAM o faltan permisos." -ForegroundColor Red
    exit
}

# Group by Usuario + AplicaciÃ³n + Ruta, show first and last execution
$grouped = $bamEntries | Group-Object Usuario, AplicaciÃ³n, 'Ruta del archivo' | ForEach-Object {
    $first = $_.Group | Sort-Object 'Hora ejecuciÃ³n UTC' | Select-Object -First 1
    $last  = $_.Group | Sort-Object 'Hora ejecuciÃ³n UTC' -Descending | Select-Object -First 1
    [PSCustomObject]@{
        'Usuario'             = $first.Usuario
        'AplicaciÃ³n'          = $first.AplicaciÃ³n
        'Ruta del archivo'    = $first.'Ruta del archivo'
        'Primera ejecuciÃ³n'   = $first.'Hora ejecuciÃ³n local'
        'Ãltima ejecuciÃ³n'    = $last.'Hora ejecuciÃ³n local'
        'Firma digital'       = $first.'Firma digital'
    }
}

if ($ExportCSV) {
    $grouped | Export-Csv -Path $CsvPath -NoTypeInformation
    Write-Host "`nExportado a $CsvPath" -ForegroundColor Green
} elseif (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
    $grouped | Out-GridView -Title "Primera y Ãºltima ejecuciÃ³n por programa y usuario"
} else {
    $grouped | Format-Table -AutoSize
}

$sw.Stop()
Write-Host "`nâ Ejecutado en $([math]::Round($sw.Elapsed.TotalSeconds,2)) segundos." 
