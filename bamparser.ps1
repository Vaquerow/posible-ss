Add-Type -AssemblyName System.Windows.Forms

function Show-OpenFileDialog {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "ETL JSON Export (*.json)|*.json"
    $dialog.Title = "Selecciona el archivo exportado de BAM (JSON)"
    $dialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")

    if ($dialog.ShowDialog() -eq "OK") {
        return $dialog.FileName
    }
    return $null
}

function Show-Timeline {
    param (
        [string]$jsonPath
    )

    if (-not (Test-Path $jsonPath)) {
        Write-Host "❌ Archivo no encontrado: $jsonPath" -ForegroundColor Red
        return
    }

    $data = Get-Content $jsonPath | ConvertFrom-Json

    if (-not $data) {
        Write-Host "❌ Error leyendo el archivo JSON." -ForegroundColor Red
        return
    }

    Write-Host "`nBAM Timeline Viewer - by ChatGPT`n" -ForegroundColor Cyan

    foreach ($entry in $data) {
        $time = $entry.Timestamp
        $msg = $entry.Message
        $type = $entry.Type

        switch ($type) {
            "Error"   { $color = "Red" }
            "Warning" { $color = "Yellow" }
            default   { $color = "White" }
        }

        Write-Host "$time`t[$type] $msg" -ForegroundColor $color
    }
}

Clear-Host

$jsonPath = Show-OpenFileDialog

if ([string]::IsNullOrWhiteSpace($jsonPath)) {
    Write-Host "❌ No se seleccionó ningún archivo." -ForegroundColor Red
} else {
    Show-Timeline -jsonPath $jsonPath
}

Write-Host "`nPulsa Enter para salir..."
[Console]::ReadLine()
