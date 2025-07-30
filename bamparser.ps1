# Requires -RunAsAdministrator

function Get-DigitalSignatureStatus($Path) {
    try {
        $signature = Get-AuthenticodeSignature -FilePath $Path
        return $signature.Status
    } catch {
        return 'Unknown'
    }
}

function Is-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $currentIdentity
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Is-Admin)) {
    Write-Warning "Este script debe ejecutarse como administrador."
    pause
    exit
}

$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"

$entries = Get-ChildItem -Path $bamPath -Recurse | ForEach-Object {
    $userSID = $_.PSChildName
    Get-ItemProperty -Path $_.PsPath | ForEach-Object {
        $appPath = $_.PSChildName
        $lastUsedStart = $_.LastUsedTimeStart
        $lastUsedStop = $_.LastUsedTimeStop

        $startTime = try {
            if ($lastUsedStart -gt 0 -and $lastUsedStart -lt [double]::MaxValue) {
                $safeVal = [Math]::Min([double]::MaxValue - 1, [double]::Parse($lastUsedStart.ToString()))
                ([datetime]'1601-01-01').AddMinutes($safeVal)
            } else {
                $null
            }
        } catch {
            $null
        }

        $stopTime = try {
            if ($lastUsedStop -gt 0 -and $lastUsedStop -lt [double]::MaxValue) {
                $safeVal = [Math]::Min([double]::MaxValue - 1, [double]::Parse($lastUsedStop.ToString()))
                ([datetime]'1601-01-01').AddMinutes($safeVal)
            } else {
                $null
            }
        } catch {
            $null
        }

        [PSCustomObject]@{
            UserSID            = $userSID
            AppPath            = $appPath
            LastUsedTimeStart  = $startTime
            LastUsedTimeStop   = $stopTime
            SignatureStatus    = Get-DigitalSignatureStatus $appPath
        }
    }
}

$entries | Sort-Object LastUsedTimeStart -Descending | Out-GridView -Title "BAM Activity Parser"
