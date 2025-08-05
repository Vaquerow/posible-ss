$ErrorActionPreference = "SilentlyContinue"

function Get-Signature {
    [CmdletBinding()]
    param (
        [string]$FilePath
    )
    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        return "Archivo no encontrado"
    }
    $status = (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue).Status
    switch ($status) {
        'Valid'        { return 'Firma válida' }
        'NotSigned'    { return 'No está firmado' }
        'HashMismatch' { return 'Firma inválida (HashMismatch)' }
        'NotTrusted'   { return 'Firma inválida (No confiable)' }
        default        { return "Firma inválida ($status)" }
    }
}

Clear-Host
Write-Host -ForegroundColor Yellow @"
 ██████╗ ██████╗ ██╗   ██╗███████╗ ██████╗ ███╗   ██╗
██╔═══██╗██╔══██╗╚██╗ ██╔╝╚══███╔╝██╔═══██╗████╗  ██║
██║   ██║██████╔╝ ╚████╔╝   ███╔╝ ██║   ██║██╔██╗ ██║
██║   ██║██╔══██╗  ╚██╔╝   ███╔╝  ██║   ██║██║╚██╗██║
╚██████╔╝██║  ██║   ██║   ███████╗╚██████╔╝██║ ╚████║
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
"@
Write-Host ""
Write-Host -ForegroundColor DarkYellow 'https://discord.gg/6P7R5XDBUf - Tranquilo, estás en manos de expertos - Vaquerow'
Write-Host ""

function Test-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (-not (Test-Admin)) {
    Write-Warning 'Ejecutá el script como Administrador.'
    Start-Sleep -Seconds 5
    Exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()

if (-not (Get-PSDrive -Name HKLM -PSProvider Registry)) {
    try { New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE }
    catch { Write-Warning 'No se pudo montar HKLM' }
}

$paths = @('bam','bam\State')
try {
    $Users = foreach ($p in $paths) {
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$p\UserSettings\" -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty PSChildName
    }
} catch {
    Write-Warning 'Falló al leer claves BAM. Verificá la versión de Windows.'
    Exit
}

$registryRoots = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\bam\',
    'HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\'
)

$tz = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
$UserBias = $tz.ActiveTimeBias

$Bam = foreach ($Sid in $Users) {
    foreach ($root in $registryRoots) {
        Write-Host -NoNewLine -ForegroundColor DarkGreen 'Analizando '
        Write-Host -ForegroundColor Cyan "$root`UserSettings\$Sid"
        try {
            $User = (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $User = 'Desconocido'
        }

        $props = Get-Item -Path "$root`UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
        foreach ($prop in $props) {
            $value = (Get-ItemProperty -Path "$root`UserSettings\$Sid" -ErrorAction SilentlyContinue).$prop
            if ($value -is [byte[]] -and $value.Length -eq 24) {
                $hex = [System.BitConverter]::ToString($value[7..0]) -replace '-',''
                $dtUtc = [DateTime]::FromFileTimeUtc([Convert]::ToInt64($hex,16))
                $TimeLocal = Get-Date $dtUtc -Format 'yyyy-MM-dd HH:mm:ss'
                $TempoBias = -([Convert]::ToInt32([Convert]::ToString($UserBias,2),2))
                $TimeUser = (Get-Date $dtUtc).AddMinutes($TempoBias).ToString('yyyy-MM-dd HH:mm:ss')

                if ($prop -match '\\Device\\HarddiskVolume') {
                    $rel = $prop.Substring(23)
                    $path = Join-Path -Path 'C:' -ChildPath $rel
                    $app  = Split-Path -Leaf $path
                }

                $sig = Get-Signature -FilePath $path

                [PSCustomObject]@{
                    'Tiempo del examinador'                         = $TimeLocal
                    'Tiempo de última ejecución (UTC)'              = $TimeLocal
                    'Tiempo de última ejecución (hora del usuario)' = $TimeUser
                    'Aplicación'                                    = $app
                    'Ruta del archivo'                              = $path
                    'Firma digital'                                 = $sig
                    'Usuario'                                       = $User
                    'SID'                                           = $Sid
                    'Ruta del registro'                             = $root
                }
            }
        }
    }
}

$Bam | Out-GridView -Title "Entradas BAM"

$sw.Stop()
Write-Host "`n✔ Ejecutado en $([math]::Round($sw.Elapsed.TotalSeconds,2)) segundos." -ForegroundColor DarkGreen @"
