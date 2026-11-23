function Test-InstaboxSecretWriteAuth {
    [CmdletBinding()]
    param()

    $apiKey = Get-InstaboxSecretValue -Name 'apiKey'
    $me = $script:InstaboxSession.Me
    if ($apiKey -and $apiKey.StartsWith('ibk_', [StringComparison]::Ordinal) -and $me -and [string]::IsNullOrWhiteSpace([string]$me.orgId)) {
        Write-Warning "Personal org API keys cannot manage org Secrets (requires org owner/admin session or a workspace API key with workspace:admin)."
    }
}

function Get-InstaboxOrgSecret {
    <#
    .SYNOPSIS
    Lists metadata (never values) for an organization's Secrets (GET /v1/orgs/{id}/secrets).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [string]$OrgId
    )

    process {
        $resp = Invoke-InstaboxRequest -Method 'GET' -Path "/v1/orgs/$([Uri]::EscapeDataString($OrgId))/secrets"
        return @($resp.Data.items)
    }
}

function Set-InstaboxOrgSecret {
    <#
    .SYNOPSIS
    Creates or replaces an organization Secret (PUT /v1/orgs/{id}/secrets/{name}).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$OrgId,

        [Parameter(Mandatory, Position = 1)]
        [string]$Name,

        [Parameter(Mandatory)]
        $Value,

        [Parameter(Mandatory)]
        [ValidateSet('proxy', 'env')]
        [string]$Delivery,

        [string[]]$Hosts
    )

    Test-InstaboxSecretWriteAuth
    $validName = Assert-InstaboxSecretName -Name $Name
    $plainValue = if ($Value -is [System.Security.SecureString]) {
        [System.Net.NetworkCredential]::new('', $Value).Password
    }
    else {
        [string]$Value
    }
    $validVal = Assert-InstaboxSecretValue -Value $plainValue -Delivery $Delivery
    $validHosts = Assert-InstaboxSecretHosts -Hosts $Hosts -Delivery $Delivery

    $body = [ordered]@{
        value    = $validVal
        delivery = $Delivery
    }
    if ($Delivery -eq 'proxy') {
        $body['hosts'] = [string[]]$validHosts
    }

    $resp = Invoke-InstaboxRequest -Method 'PUT' -Path "/v1/orgs/$([Uri]::EscapeDataString($OrgId))/secrets/$([Uri]::EscapeDataString($validName))" -Body $body
    return $resp.Data
}

function Remove-InstaboxOrgSecret {
    <#
    .SYNOPSIS
    Deletes an organization Secret and removes its explicit sandbox grants (DELETE /v1/orgs/{id}/secrets/{name}).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$OrgId,

        [Parameter(Mandatory, Position = 1)]
        [string]$Name,

        [switch]$Force
    )

    Test-InstaboxSecretWriteAuth
    $validName = Assert-InstaboxSecretName -Name $Name
    if (-not $Force -and -not $PSCmdlet.ShouldProcess("$OrgId/$validName", 'Delete org Secret and explicit sandbox grants')) {
        return
    }

    Invoke-InstaboxRequest -Method 'DELETE' -Path "/v1/orgs/$([Uri]::EscapeDataString($OrgId))/secrets/$([Uri]::EscapeDataString($validName))" | Out-Null
    return [PSCustomObject]@{ Deleted = $true; OrgId = $OrgId; Name = $validName }
}

function Import-InstaboxOrgSecret {
    <#
    .SYNOPSIS
    Atomically creates or replaces a batch of organization Secrets from a hashtable or .env file (POST /v1/orgs/{id}/secrets/import).
    #>
    [CmdletBinding(DefaultParameterSetName = 'FromFile')]
    param(
        [Parameter(ParameterSetName = 'FromFile', Mandatory, Position = 0)]
        [Parameter(ParameterSetName = 'FromMap', Mandatory, Position = 0)]
        [string]$OrgId,

        [Parameter(ParameterSetName = 'FromFile', Mandatory)]
        [string]$EnvFile,

        [Parameter(ParameterSetName = 'FromMap', Mandatory)]
        [System.Collections.IDictionary]$Values,

        [Parameter(Mandatory)]
        [ValidateSet('proxy', 'env')]
        [string]$Delivery,

        [string[]]$Hosts
    )

    Test-InstaboxSecretWriteAuth
    $rawMap = if ($PSCmdlet.ParameterSetName -eq 'FromFile') {
        if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
            throw [System.IO.FileNotFoundException]::new("Env file '$EnvFile' not found.", $EnvFile)
        }
        $content = Get-Content -LiteralPath $EnvFile -Raw -Encoding utf8
        ConvertFrom-InstaboxDotEnv -Content $content
    }
    else {
        $Values
    }

    if ($null -eq $rawMap -or $rawMap.Count -eq 0) {
        throw [System.ArgumentException]::new("At least one Secret entry is required for import.")
    }

    $validHosts = Assert-InstaboxSecretHosts -Hosts $Hosts -Delivery $Delivery
    $cleanValues = [ordered]@{}
    foreach ($k in $rawMap.Keys) {
        $vk = Assert-InstaboxSecretName -Name ([string]$k)
        $vv = Assert-InstaboxSecretValue -Value ([string]$rawMap[$k]) -Delivery $Delivery
        $cleanValues[$vk] = $vv
    }

    $body = [ordered]@{
        values   = $cleanValues
        delivery = $Delivery
    }
    if ($Delivery -eq 'proxy') {
        $body['hosts'] = [string[]]$validHosts
    }

    $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/orgs/$([Uri]::EscapeDataString($OrgId))/secrets/import" -Body $body
    return @($resp.Data.items)
}

function Get-InstaboxSandboxSecret {
    <#
    .SYNOPSIS
    Reads a sandbox's Secret selections, proxy status, guest status, and proxied usage metadata (GET /v1/machines/{id}/secrets).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $resp = Invoke-InstaboxRequest -Method 'GET' -Path "/v1/machines/$validId/secrets"
        return $resp.Data
    }
}

function Set-InstaboxSandboxSecret {
    <#
    .SYNOPSIS
    Replaces supplied Secret selections on a sandbox (PATCH /v1/machines/{id}/secrets).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        $ProxySecrets,

        [string[]]$EnvSecrets,

        [object[]]$DirectSecrets
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        if ($PSBoundParameters.ContainsKey('EnvSecrets') -and $PSBoundParameters.ContainsKey('DirectSecrets')) {
            throw [System.ArgumentException]::new("-EnvSecrets and -DirectSecrets cannot be supplied together.")
        }

        $body = [ordered]@{}
        if ($PSBoundParameters.ContainsKey('ProxySecrets')) {
            if ($null -eq $ProxySecrets) {
                throw [System.ArgumentException]::new("-ProxySecrets cannot be null (use @() to clear or 'all' for all).")
            }
            if ($ProxySecrets -is [string] -and $ProxySecrets -eq 'all') {
                $body['secrets'] = 'all'
            }
            else {
                $arr = @($ProxySecrets | ForEach-Object { Assert-InstaboxSecretName -Name ([string]$_) })
                $body['secrets'] = [string[]]$arr
            }
        }
        if ($PSBoundParameters.ContainsKey('EnvSecrets')) {
            if ($null -eq $EnvSecrets) {
                throw [System.ArgumentException]::new("-EnvSecrets cannot be null (use @() to clear).")
            }
            $arr = @($EnvSecrets | ForEach-Object { Assert-InstaboxSecretName -Name ([string]$_) })
            $body['envSecrets'] = [string[]]$arr
        }
        if ($PSBoundParameters.ContainsKey('DirectSecrets')) {
            if ($null -eq $DirectSecrets) {
                throw [System.ArgumentException]::new("-DirectSecrets cannot be null (use @() to clear).")
            }
            if ($DirectSecrets.Count -gt 64) {
                throw [System.ArgumentException]::new("At most 64 directSecrets items are allowed.")
            }
            if ($script:InstaboxSession.Me -and ($null -eq $script:InstaboxSession.Me.PSObject.Properties['directSecretRefs'] -or -not [bool]$script:InstaboxSession.Me.directSecretRefs)) {
                Write-Warning "Server /v1/me did not advertise directSecretRefs=true; directSecrets may be rejected with 400."
            }
            $body['directSecrets'] = @($DirectSecrets)
        }

        if ($body.Count -eq 0) {
            throw [System.ArgumentException]::new("Specify at least one of -ProxySecrets, -EnvSecrets, or -DirectSecrets.")
        }

        $resp = Invoke-InstaboxRequest -Method 'PATCH' -Path "/v1/machines/$validId/secrets" -Body $body
        return $resp.Data
    }
}

function Sync-InstaboxSandboxSecret {
    <#
    .SYNOPSIS
    Refreshes managed Secret delivery and proxy reconciliation on a running sandbox (POST /v1/machines/{id}/secrets).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/secrets"
        return $resp.Data
    }
}
