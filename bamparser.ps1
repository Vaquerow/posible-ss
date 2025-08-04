$ErrorActionPreference = "SilentlyContinue"

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
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-DigitalSignatureStatus {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath -PathType Leaf)) { return "File not found" }
    $status = (Get-AuthenticodeSignature -FilePath $FilePath).Status
    switch ($status) {
        'Valid'        { return 'Valid' }
        'NotSigned'    { return 'Not signed' }
        'HashMismatch' { return 'Invalid (HashMismatch)' }
        'NotTrusted'   { return 'Invalid (Not trusted)' }
        default        { return "Invalid ($status)" }
    }
}

function Get-BamUsers {
    $bamPaths = @('bam', 'bam\State')
    $users = @()
    foreach ($p in $bamPaths) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$p\UserSettings\"
        if (Test-Path $key) {
            $users += Get-ChildItem -Path $key | Select-Object -ExpandProperty PSChildName
        }
    }
    return $users | Sort-Object -Unique
}

function Convert-DevicePathToDrivePath {
    param([string]$DevicePath)
    if ($DevicePath -match '\\Device\\HarddiskVolume(\d+)\\(.+)') {
        $drive = "C:" # Most common, adjust if needed
        $relative = $Matches[2] -replace '\\','\'
        return "$drive\$relative"
    }
    return $DevicePath
}

function Get-BamEntries {
    $users = Get-BamUsers
    $roots = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\',
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\'
    )
    $tz = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
    $userBias = $tz.ActiveTimeBias

    $entries = @()
    foreach ($sid in $users) {
        foreach ($root in $roots) {
            $userKey = "${root}UserSettings\$sid"
            if (-not (Test-Path $userKey)) { continue }
            try {
                $user = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
            } catch { $user = 'Unknown' }
            $props = (Get-Item -Path $userKey).Property
            foreach ($prop in $props) {
                $value = (Get-ItemProperty -Path $userKey).$prop
                if ($value -is [byte[]] -and $value.Length -eq 24) {
                    $hex = [System.BitConverter]::ToString($value[7..0]) -replace '-',''
                    $dtUtc = [DateTime]::FromFileTimeUtc([Convert]::ToInt64($hex,16))
                    $localTime = $dtUtc.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                    $userTime = ($dtUtc).AddMinutes(-1 * $userBias).ToString('yyyy-MM-dd HH:mm:ss')
                    $filePath = Convert-DevicePathToDrivePath -DevicePath $prop
                    $appName = Split-Path -Leaf $filePath
                    $signature = Get-DigitalSignatureStatus -FilePath $filePath

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

# Main
Clear-Host
Show-Banner

if (-not (Test-Admin)) {
    Write-Warning "Please run this script as Administrator."
    Start-Sleep -Seconds 5
    exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()
$bamEntries = Get-BamEntries

if ($bamEntries.Count -eq 0) {
    Write-Host "No BAM entries found or insufficient permissions." -ForegroundColor Red
    exit
}

$bamEntries | Out-GridView -Title "BAM Executed Programs"
$sw.Stop()
Write-Host "`n✔ Completed in $([math]::Round($sw.Elapsed.TotalSeconds,2)) seconds." -ForegroundColor Green
