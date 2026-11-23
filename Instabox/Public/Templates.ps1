function Get-InstaboxTemplate {
    <#
    .SYNOPSIS
    Lists templates a sandbox can start from (GET /v1/templates).
    #>
    [CmdletBinding()]
    param(
        [switch]$CreatableOnly,

        [switch]$LatestOnly,

        [string]$Id
    )

    $resp = Invoke-InstaboxRequest -Method 'GET' -Path '/v1/templates'
    $templates = @($resp.Data.templates)

    if (-not [string]::IsNullOrWhiteSpace($Id)) {
        $templates = @($templates | Where-Object { $_.id -eq $Id })
    }

    if ($CreatableOnly) {
        $templates = @($templates | Where-Object {
            if ($null -ne $_.PSObject.Properties['creatable'] -and $null -ne $_.creatable) {
                return [bool]$_.creatable
            }
            return (-not [bool]$_.hidden)
        })
    }

    if ($LatestOnly) {
        $byId = [ordered]@{}
        foreach ($t in $templates) {
            $tid = [string]$t.id
            if (-not $byId.Contains($tid)) {
                $byId[$tid] = [System.Collections.Generic.List[object]]::new()
            }
            $byId[$tid].Add($t)
        }
        $latestList = [System.Collections.Generic.List[object]]::new()
        foreach ($tid in $byId.Keys) {
            $group = $byId[$tid]
            $explicit = $group | Where-Object { [bool]$_.latest } | Select-Object -First 1
            if ($explicit) {
                $latestList.Add($explicit)
            }
            else {
                $fallback = $group | Where-Object { -not [bool]$_.hidden } | Select-Object -Last 1
                if ($fallback) { $latestList.Add($fallback) }
            }
        }
        return $latestList.ToArray()
    }

    return $templates
}
