$ErrorActionPreference = 'SilentlyContinue'

function Get-DigitalSignatureStatus {
    param ([string]$Path)
    if (-not (Test-Path $Path)) {
        return 'Archivo no encontrado'
    }
    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    switch ($sig.Status) {
        'Valid'        { 'Firma válida' }
        'NotSigned'    { 'No está firmado' }
        'HashMismatch' { 'Firma inválida (HashMismatch)' }
        'NotTrusted'   { 'Firma inválida (No confiable)' }
        default        { "Firma inválida ($($sig.Status))" }
    }
}

function Is-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Is-Admin)) {
    Write-Warning 'Por favor ejecutá este script como Administrador.'
    Start-Sleep -Seconds 5
    exit
}

Write-Host "`n--- BAM Parser v2 ---`n" -ForegroundColor Cyan

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

$bamKeys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings',
    'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
)

$tzInfo = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
$userBias = $tzInfo.ActiveTimeBias

$entries = @()

foreach ($bamKey in $bamKeys) {
    $userSIDs = Get-ChildItem -Path $bamKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName

    foreach ($sid in $userSIDs) {
        try {
            $username = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount])
        } catch {
            $username = 'Desconocido'
        }

        $userPath = Join-Path $bamKey $sid
        $props = (Get-ItemProperty -Path $userPath).PSObject.Properties | Where-Object { $_.Value -is [byte[]] -and $_.Value.Length -eq 24 }

        foreach ($entry in $props) {
            $rawBytes = $entry.Value[0..7]
            [Array]::Reverse($rawBytes)
            $fileTime = [BitConverter]::ToInt64($rawBytes, 0)
            $utcDate = [DateTime]::FromFileTimeUtc($fileTime)
            $localDate = $utcDate.AddMinutes(-$userBias)

            $exePath = if ($entry.Name -match '\\Device\\HarddiskVolume\d+\\(.+)$') { "C:\$($Matches[1])" } else { 'Ruta no reconocida' }
            $appName = Split-Path -Path $exePath -Leaf

            $entries += [PSCustomObject]@{
                'Fecha (UTC)'       = $utcDate.ToString('yyyy-MM-dd HH:mm:ss')
                'Fecha (Local)'     = $localDate.ToString('yyyy-MM-dd HH:mm:ss')
                'Aplicación'         = $appName
                'Ruta del archivo'  = $exePath
                'Firma digital'     = Get-DigitalSignatureStatus -Path $exePath
                'Usuario'           = $username
                'SID'               = $sid
                'Registro'          = $bamKey
            }
        }
    }
}

$entries | Out-GridView -Title 'Resultados del Análisis BAM'

$stopwatch.Stop()
Write-Host "`nAnálisis finalizado en $($stopwatch.Elapsed.TotalSeconds) segundos." -ForegroundColor Green
