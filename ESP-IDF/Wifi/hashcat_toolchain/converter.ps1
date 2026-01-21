# add_offsets.ps1
$in  = ".\hexdump.txt"
$out = ".\hexdump_with_offsets.txt"

$offset = 0
$linesOut = New-Object System.Collections.Generic.List[string]

Get-Content $in | ForEach-Object {
    $line = $_.Trim()

    if ($line -eq "") {
        # Paketgrenze: Leerzeile schreiben, Offset zurücksetzen
        $linesOut.Add("")
        $offset = 0
        return
    }

    # Alle Hex-Token einsammeln (zweistellige Bytes)
    $bytes = ($line -split '\s+') | Where-Object { $_ -match '^[0-9A-Fa-f]{2}$' }

    # in 16er-Blöcke umbrochen, pro Zeile Offset + 16 Bytes
    for ($i=0; $i -lt $bytes.Count; $i += 16) {
        $chunk = $bytes[$i..([Math]::Min($i+15, $bytes.Count-1))]
        $offStr = '{0:X6}' -f $offset    # 6-stelliger Hex-Offset: 000000, 000010, ...
        $linesOut.Add( ($offStr + " " + ($chunk -join " ")) )
        $offset += $chunk.Count
    }
}

$linesOut | Set-Content -Encoding ASCII $out
Write-Host "Wrote $out"
