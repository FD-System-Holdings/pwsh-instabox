function ConvertFrom-InstaboxDotEnv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content
    )

    $result = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Content)) {
        return $result
    }

    $lines = $Content -split "\r?\n"
    foreach ($rawLine in $lines) {
        $line = $rawLine.Trim()
        if ([string]::IsNullOrEmpty($line) -or $line.StartsWith('#')) {
            continue
        }
        if ($line -match '^export\s+(.+)$') {
            $line = $Matches[1].TrimStart()
        }
        $eqIdx = $line.IndexOf('=')
        if ($eqIdx -le 0) {
            throw [System.FormatException]::new("Invalid .env line (missing '='): $rawLine")
        }

        $key = $line.Substring(0, $eqIdx).Trim()
        $valPart = $line.Substring($eqIdx + 1)

        $trimmedStart = $valPart.TrimStart()
        if ($trimmedStart.StartsWith('"')) {
            # Parse double-quoted string with escapes
            $sb = [System.Text.StringBuilder]::new()
            $escaped = $false
            $closed = $false
            for ($i = 1; $i -lt $trimmedStart.Length; $i++) {
                $ch = $trimmedStart[$i]
                if ($escaped) {
                    switch ($ch) {
                        'n' { [void]$sb.Append("`n") }
                        'r' { [void]$sb.Append("`r") }
                        't' { [void]$sb.Append("`t") }
                        '"' { [void]$sb.Append('"') }
                        '\' { [void]$sb.Append('\') }
                        default { [void]$sb.Append($ch) }
                    }
                    $escaped = $false
                }
                elseif ($ch -eq '\') {
                    $escaped = $true
                }
                elseif ($ch -eq '"') {
                    $closed = $true
                    break
                }
                else {
                    [void]$sb.Append($ch)
                }
            }
            if (-not $closed) {
                throw [System.FormatException]::new("Unterminated double-quoted value in .env for key '$key'.")
            }
            $result[$key] = $sb.ToString()
        }
        elseif ($trimmedStart.StartsWith("'")) {
            # Parse single-quoted string (literal until matching quote)
            $endIdx = $trimmedStart.IndexOf("'", 1)
            if ($endIdx -lt 0) {
                throw [System.FormatException]::new("Unterminated single-quoted value in .env for key '$key'.")
            }
            $result[$key] = $trimmedStart.Substring(1, $endIdx - 1)
        }
        else {
            # Unquoted value: strip inline comment preceded by whitespace
            $val = $trimmedStart
            if ($val -match '^(.*?)\s+#.*$') {
                $val = $Matches[1]
            }
            $result[$key] = $val.Trim()
        }
    }

    return $result
}
