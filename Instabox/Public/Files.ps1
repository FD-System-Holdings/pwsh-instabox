function Get-InstaboxFile {
    <#
    .SYNOPSIS
    Lists a directory or reads a UTF-8 text file (<= 256 KiB) from a running sandbox (GET /v1/machines/{id}/files).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [Parameter(Position = 1)]
        [string]$Path = '/'
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $validPath = Assert-InstaboxFilePath -Path $Path
        $sem = Get-InstaboxFsSemaphore
        $sem.Wait()
        try {
            $resp = Invoke-InstaboxRequest -Method 'GET' -Path "/v1/machines/$validId/files" -Query @{ path = $validPath }
            return $resp.Data
        }
        finally {
            [void]$sem.Release()
        }
    }
}

function Receive-InstaboxFile {
    <#
    .SYNOPSIS
    Downloads raw file bytes from a running sandbox with ETag/Range resume support (GET /v1/machines/{id}/files/content).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [Parameter(Mandatory, Position = 1)]
        [string]$RemotePath,

        [Parameter(Position = 2)]
        [string]$LocalPath,

        [switch]$Resume,

        [ValidateRange(0, 20)]
        [int]$MaxResumeAttempts = 3
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $validPath = Assert-InstaboxFilePath -Path $RemotePath -NoTrailingSlash
        return (Invoke-InstaboxFileDownload -MachineId $validId -RemotePath $validPath -LocalPath $LocalPath -Resume:$Resume -MaxResumeAttempts $MaxResumeAttempts)
    }
}

function Send-InstaboxFile {
    <#
    .SYNOPSIS
    Uploads raw bytes to a file in a running sandbox with SHA-256 verification (PUT /v1/machines/{id}/files).
    #>
    [CmdletBinding(DefaultParameterSetName = 'FromFile')]
    param(
        [Parameter(ParameterSetName = 'FromFile', Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'FromBytes', Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'FromText', Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SignedUrlFile', Position = 0)]
        [Alias('MachineId')]
        [string]$Id,

        [Parameter(ParameterSetName = 'FromFile', Mandatory, Position = 1)]
        [Parameter(ParameterSetName = 'FromBytes', Mandatory, Position = 1)]
        [Parameter(ParameterSetName = 'FromText', Mandatory, Position = 1)]
        [Parameter(ParameterSetName = 'SignedUrlFile')]
        [string]$RemotePath,

        [Parameter(ParameterSetName = 'FromFile', Mandatory)]
        [Parameter(ParameterSetName = 'SignedUrlFile', Mandatory)]
        [string]$LocalPath,

        [Parameter(ParameterSetName = 'FromBytes', Mandatory)]
        [byte[]]$Bytes,

        [Parameter(ParameterSetName = 'FromText', Mandatory)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(ParameterSetName = 'FromFile')]
        [Parameter(ParameterSetName = 'FromBytes')]
        [Parameter(ParameterSetName = 'FromText')]
        [string]$Mode,

        [Parameter(ParameterSetName = 'FromFile')]
        [Parameter(ParameterSetName = 'FromBytes')]
        [Parameter(ParameterSetName = 'FromText')]
        [switch]$Parents,

        [Parameter(ParameterSetName = 'FromFile')]
        [Parameter(ParameterSetName = 'FromBytes')]
        [Parameter(ParameterSetName = 'FromText')]
        [string]$Token,

        [Parameter(ParameterSetName = 'SignedUrlFile', Mandatory)]
        [string]$SignedUploadUrl
    )

    process {
        $maxBytes = 5368709120L # 5 GiB
        $validMode = if (-not [string]::IsNullOrWhiteSpace($Mode)) { Assert-InstaboxOctalMode -Mode $Mode } else { $null }

        $stream = $null
        $shaHex = $null

        try {
            if ($PSCmdlet.ParameterSetName -in @('FromFile', 'SignedUrlFile')) {
                if (-not (Test-Path -LiteralPath $LocalPath -PathType Leaf)) {
                    throw [System.IO.FileNotFoundException]::new("Local file '$LocalPath' not found.", $LocalPath)
                }
                $fi = Get-Item -LiteralPath $LocalPath
                if ($fi.Length -gt $maxBytes) {
                    throw [System.ArgumentException]::new("File '$LocalPath' ($($fi.Length) bytes) exceeds the 5 GiB upload limit.")
                }
                $shaHex = (Get-FileHash -LiteralPath $LocalPath -Algorithm SHA256).Hash.ToLowerInvariant()
                $stream = [System.IO.File]::OpenRead($LocalPath)
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'FromBytes') {
                if ($Bytes.LongLength -gt $maxBytes) {
                    throw [System.ArgumentException]::new("Payload exceeds 5 GiB upload limit.")
                }
                $sha = [System.Security.Cryptography.SHA256]::HashData($Bytes)
                $shaHex = ([BitConverter]::ToString($sha) -replace '-', '').ToLowerInvariant()
                $stream = [System.IO.MemoryStream]::new($Bytes, $false)
            }
            else {
                $rawBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
                $sha = [System.Security.Cryptography.SHA256]::HashData($rawBytes)
                $shaHex = ([BitConverter]::ToString($sha) -replace '-', '').ToLowerInvariant()
                $stream = [System.IO.MemoryStream]::new($rawBytes, $false)
            }

            if ($PSCmdlet.ParameterSetName -eq 'SignedUrlFile') {
                return (Invoke-InstaboxFileUpload -SignedUploadUrl $SignedUploadUrl -InputStream $stream -ExpectedSha256 $shaHex)
            }

            $validId = Assert-InstaboxMachineId -Id $Id
            $validPath = Assert-InstaboxFilePath -Path $RemotePath -NoTrailingSlash
            return (Invoke-InstaboxFileUpload -MachineId $validId -RemotePath $validPath -Mode $validMode -Parents:$Parents -Token $Token -InputStream $stream -ExpectedSha256 $shaHex)
        }
        finally {
            if ($null -ne $stream) {
                $stream.Dispose()
            }
        }
    }
}

function New-InstaboxUploadUrl {
    <#
    .SYNOPSIS
    Creates a short-lived HMAC-signed URL to upload one file without sending your API key (POST /v1/machines/{id}/files/upload-url).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [Parameter(Mandatory, Position = 1)]
        [string]$Path,

        [string]$Mode,

        [switch]$Parents,

        [ValidateRange(1, 3600)]
        [int]$ExpiresInSeconds = 900
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $validPath = Assert-InstaboxFilePath -Path $Path -NoTrailingSlash
        $body = [ordered]@{ path = $validPath }
        if (-not [string]::IsNullOrWhiteSpace($Mode)) { $body['mode'] = Assert-InstaboxOctalMode -Mode $Mode }
        if ($Parents) { $body['parents'] = $true }
        if ($PSBoundParameters.ContainsKey('ExpiresInSeconds')) { $body['expiresInSeconds'] = $ExpiresInSeconds }

        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/files/upload-url" -Body $body
        return $resp.Data
    }
}

function New-InstaboxDirectory {
    <#
    .SYNOPSIS
    Creates a directory on a running sandbox via exec argv (mkdir -p) with noHistory=true.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [Parameter(Mandatory, Position = 1)]
        [string]$Path
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $validPath = Assert-InstaboxFilePath -Path $Path
        $res = Invoke-InstaboxExec -Id $validId -Argv @('mkdir', '-p', '--', $validPath) -NoHistory -NoKeepalive
        if ($res.exitCode -ne 0) {
            throw [System.IO.IOException]::new("mkdir -p '$validPath' failed (exit $($res.exitCode)): $($res.stderr)")
        }
        return [PSCustomObject]@{ Created = $true; Path = $validPath }
    }
}

function Rename-InstaboxFile {
    <#
    .SYNOPSIS
    Moves or renames a file/directory on a running sandbox via exec argv (mv) with noHistory=true.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [Parameter(Mandatory, Position = 1)]
        [string]$SourcePath,

        [Parameter(Mandatory, Position = 2)]
        [string]$DestinationPath,

        [switch]$Force
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $src = Assert-InstaboxFilePath -Path $SourcePath
        $dst = Assert-InstaboxFilePath -Path $DestinationPath
        $argv = if ($Force) { @('mv', '-f', '--', $src, $dst) } else { @('mv', '-n', '--', $src, $dst) }
        $res = Invoke-InstaboxExec -Id $validId -Argv $argv -NoHistory -NoKeepalive
        if ($res.exitCode -ne 0) {
            throw [System.IO.IOException]::new("mv '$src' -> '$dst' failed (exit $($res.exitCode)): $($res.stderr)")
        }
        return [PSCustomObject]@{ Source = $src; Destination = $dst }
    }
}

function Remove-InstaboxFile {
    <#
    .SYNOPSIS
    Deletes a file or directory on a running sandbox via exec argv (rm) with noHistory=true.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$Id,

        [Parameter(Mandatory, Position = 1)]
        [string]$Path,

        [switch]$Recursive,

        [switch]$Force
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $Id
        $validPath = Assert-InstaboxFilePath -Path $Path
        if ($validPath -eq '/') {
            throw [System.ArgumentException]::new("Refusing to remove '/' on sandbox '$validId'.")
        }
        if (-not $Force -and -not $PSCmdlet.ShouldProcess("$validId`:$validPath", 'Remove remote path')) {
            return
        }
        $argv = if ($Recursive) { @('rm', '-rf', '--', $validPath) } else { @('rm', '-f', '--', $validPath) }
        $res = Invoke-InstaboxExec -Id $validId -Argv $argv -NoHistory -NoKeepalive
        if ($res.exitCode -ne 0) {
            throw [System.IO.IOException]::new("rm '$validPath' failed (exit $($res.exitCode)): $($res.stderr)")
        }
        return [PSCustomObject]@{ Deleted = $true; Path = $validPath }
    }
}
