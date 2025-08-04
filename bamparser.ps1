function Resolve-DigitalSignature {
    param([string]$Path)
    if (!(Test-Path $Path)) { return 'No encontrado' }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path
        switch ($sig.Status) {
            'Valid' { 'Válida' }
            'NotSigned' { 'No Firmado' }
            'HashMismatch' { 'Hash no coincide' }
            'NotTrusted' { 'No confiable' }
            default { "Desconocido ($($sig.Status))" }
        }
    } catch {
        'Error al verificar'
    }
}

function Require-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Warning "Este script necesita privilegios de Administrador."
        Start-Sleep 3
        exit
    }
}

Require-Admin

Clear-Host
Write-Host -ForegroundColor Cyan @"
╔════════════════════════════════════════════╗
║        BAM Timeline Viewer - by ChatGPT    ║
╚════════════════════════════════════════════╝
"@

$bamRoots = @( 
    'HKLM:\SYSTEM\CurrentControlSet\Services\BAM\UserSettings',
    'HKLM:\SYSTEM\CurrentControlSet\Services\BAM\State\UserSettings'
)

$entries = @()

foreach ($root in $bamRoots) {
    $sids = Get-ChildItem -Path $root -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName

    foreach ($sid in $sids) {
        try {
            $user = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $user = 'Desconocido'
        }

        $keyPath = Join-Path $root $sid
        $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
        foreach ($name in $props.PSObject.Properties.Name) {
            $raw = $props.$name
            if ($raw -is [byte[]] -and $raw.Length -ge 8) {
                $ticks = [BitConverter]::ToInt64($raw[0..7], 0)
                try {
                    $utcTime = [DateTime]::FromFileTimeUtc($ticks)
                } catch {
                    $utcTime = $null
                }

                $path = ''
                $app  = ''
                if ($name -match '\\Device\\HarddiskVolume') {
                    $rel = $name.Substring(23)
                    $path = Join-Path 'C:\' $rel
                    $app  = Split-Path -Leaf $path
                }

                $entries += [PSCustomObject]@{
                    'Usuario'         = $user
                    'SID'             = $sid
                    'Aplicación'      = $app
                    'Ruta'            = $path
                    'Fecha de uso UTC'= $utcTime
                    'Firma'           = Resolve-DigitalSignature -Path $path
                    'Clave Registro'  = $keyPath
                }
            }
        }
    }
}

$entries | Sort-Object 'Fecha de uso UTC' -Descending | Out-GridView -Title "Análisis BAM"
