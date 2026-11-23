function Get-InstaboxPort {
    <#
    .SYNOPSIS
    Lists published ports across all non-deleted sandboxes (GET /v1/ports) or for a single sandbox (GET /v1/machines/{id}/ports).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('Id', 'MachineId')]
        [string]$SandboxId
    )

    process {
        if (-not [string]::IsNullOrWhiteSpace($SandboxId)) {
            $validId = Assert-InstaboxMachineId -Id $SandboxId
            $resp = Invoke-InstaboxRequest -Method 'GET' -Path "/v1/machines/$validId/ports"
            return $resp.Data
        }

        $resp = Invoke-InstaboxRequest -Method 'GET' -Path '/v1/ports'
        return $resp.Data
    }
}

function Publish-InstaboxPort {
    <#
    .SYNOPSIS
    Publishes or updates an HTTP (public/private) or raw TCP port on a sandbox (POST /v1/machines/{id}/ports).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('Id', 'MachineId')]
        [string]$SandboxId,

        [Parameter(Mandatory, Position = 1)]
        [int]$Port,

        [string]$Name,

        [ValidateSet('http', 'tcp')]
        [string]$Protocol,

        [ValidateSet('public', 'private')]
        [string]$Access,

        [switch]$RotateToken
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $SandboxId
        $validPort = Assert-InstaboxPort -Port $Port

        if ($Protocol -eq 'tcp' -and $Access -eq 'private') {
            throw [System.ArgumentException]::new("Raw TCP ports cannot be private (only HTTP ports support access='private').")
        }
        if ($RotateToken -and $Access -eq 'public') {
            throw [System.ArgumentException]::new("-RotateToken applies only to private HTTP ports.")
        }

        $body = [ordered]@{ port = $validPort }
        if (-not [string]::IsNullOrWhiteSpace($Name)) {
            if ($Name.Length -gt 100) {
                throw [System.ArgumentException]::new("Port name cannot exceed 100 characters.")
            }
            $body['name'] = $Name
        }
        if (-not [string]::IsNullOrWhiteSpace($Protocol)) { $body['protocol'] = $Protocol }
        if (-not [string]::IsNullOrWhiteSpace($Access)) { $body['access'] = $Access }
        if ($RotateToken) { $body['rotateToken'] = $true }

        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/ports" -Body $body
        $pub = $resp.Data

        if ($pub.id -and ($pub.token -or $pub.tokenUrl)) {
            $cacheEntry = [ordered]@{
                token     = [string]$pub.token
                tokenUrl  = [string]$pub.tokenUrl
                machineId = $validId
                port      = [int]$pub.port
            } | ConvertTo-Json -Compress
            Set-InstaboxSecretValue -Name "portToken:$($pub.id)" -Value $cacheEntry
        }

        return $pub
    }
}

function Unpublish-InstaboxPort {
    <#
    .SYNOPSIS
    Removes a port's public URL and closes active connections (DELETE /v1/machines/{id}/ports/{port}).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('Id', 'MachineId')]
        [string]$SandboxId,

        [Parameter(Mandatory, Position = 1)]
        [int]$Port,

        [switch]$Force
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $SandboxId
        $validPort = Assert-InstaboxPort -Port $Port

        if (-not $Force -and -not $PSCmdlet.ShouldProcess("$validId`:$validPort", 'Unpublish port and close active connections')) {
            return
        }

        # Clean up any locally cached private port token for this sandbox+port if known
        $secretMap = Get-InstaboxSecretMap
        foreach ($k in @($secretMap.Keys)) {
            if ($k.StartsWith('portToken:', [StringComparison]::Ordinal)) {
                try {
                    $raw = Get-InstaboxSecretValue -Name $k
                    $obj = $raw | ConvertFrom-Json
                    if ($obj.machineId -eq $validId -and [int]$obj.port -eq $validPort) {
                        Remove-InstaboxSecretValue -Name $k
                    }
                }
                catch { }
            }
        }

        Invoke-InstaboxRequest -Method 'DELETE' -Path "/v1/machines/$validId/ports/$validPort" | Out-Null
        return [PSCustomObject]@{ Unpublished = $true; MachineId = $validId; Port = $validPort }
    }
}

function Get-InstaboxPortToken {
    <#
    .SYNOPSIS
    Retrieves a locally cached private port token (ibp_...) and tokenUrl for a published port ID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [string]$PortId
    )

    process {
        $raw = Get-InstaboxSecretValue -Name "portToken:$PortId"
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $null
        }
        return ($raw | ConvertFrom-Json)
    }
}
