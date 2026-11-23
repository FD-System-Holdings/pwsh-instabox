function Get-InstaboxSnapshot {
    <#
    .SYNOPSIS
    Lists snapshots of your orgs (GET /v1/snapshots) or gets one snapshot by ID (GET /v1/snapshots/{id}).
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param(
        [Parameter(ParameterSetName = 'ById', Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('SnapshotId')]
        [string]$Id
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            $validId = Assert-InstaboxSnapshotId -Id $Id
            $resp = Invoke-InstaboxRequest -Method 'GET' -Path "/v1/snapshots/$validId"
            return $resp.Data
        }

        $resp = Invoke-InstaboxRequest -Method 'GET' -Path '/v1/snapshots'
        return @($resp.Data.snapshots)
    }
}

function New-InstaboxSnapshot {
    <#
    .SYNOPSIS
    Saves a sandbox's system files and storage (unless -RootOnly) as a snapshot (POST /v1/machines/{id}/snapshots).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('Id', 'MachineId')]
        [string]$SandboxId,

        [Parameter(Mandatory, Position = 1)]
        [string]$Name,

        [string]$Description,

        [switch]$RootOnly,

        [switch]$ForFork,

        [string]$IdempotencyKey,

        [switch]$Wait,

        [ValidateRange(5, 3600)]
        [int]$WaitTimeoutSeconds = 600
    )

    process {
        $validId = Assert-InstaboxMachineId -Id $SandboxId
        $validName = Assert-InstaboxResourceName -Name $Name -Kind 'snapshot'

        if (-not $RootOnly) {
            Write-InstaboxLog -Level 'INFO' -Message "Creating full snapshot '$validName' for $validId (includes /data/home credentials and is shared with the sandbox's org)."
        }

        $body = [ordered]@{ name = $validName }
        if (-not [string]::IsNullOrWhiteSpace($Description)) { $body['description'] = $Description }
        if ($RootOnly) { $body['rootOnly'] = $true }
        if ($ForFork) { $body['forFork'] = $true }

        $resp = Invoke-InstaboxRequest -Method 'POST' -Path "/v1/machines/$validId/snapshots" -Body $body -RequireIdempotency -IdempotencyKey $IdempotencyKey
        $snap = $resp.Data

        if ($Wait -and $snap.status -eq 'pending') {
            $deadline = [DateTimeOffset]::UtcNow.AddSeconds($WaitTimeoutSeconds)
            try {
                while ($snap.status -eq 'pending') {
                    Write-Progress -Activity "Snapshot $($snap.id)" -Status "Waiting for snapshot upload (status: $($snap.status))"
                    if ([DateTimeOffset]::UtcNow -ge $deadline) {
                        throw [System.TimeoutException]::new("Timed out waiting for snapshot '$($snap.id)' to become ready.")
                    }
                    $delayMs = [int][Math]::Round(1000 * [double]$script:InstaboxSession.RetryDelayScale)
                    if ($delayMs -gt 0) { Start-Sleep -Milliseconds $delayMs }
                    $snap = Get-InstaboxSnapshot -Id $snap.id
                }
            }
            finally {
                Write-Progress -Activity "Snapshot $($snap.id)" -Completed
            }

            if ($snap.status -eq 'failed') {
                throw [System.InvalidOperationException]::new("Snapshot '$($snap.id)' failed: $($snap.error)")
            }
        }

        return $snap
    }
}

function Remove-InstaboxSnapshot {
    <#
    .SYNOPSIS
    Deletes a snapshot (DELETE /v1/snapshots/{id}) with X-Confirm-Delete confirmation.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('SnapshotId')]
        [string]$Id,

        [string]$ConfirmName,

        [switch]$Force,

        [string]$IdempotencyKey
    )

    process {
        $validId = Assert-InstaboxSnapshotId -Id $Id
        $confirmHeader = $ConfirmName

        if ([string]::IsNullOrWhiteSpace($confirmHeader)) {
            if ($Force) {
                $confirmHeader = $validId
            }
            else {
                $snap = Get-InstaboxSnapshot -Id $validId
                $expectedName = [string]$snap.name
                if ([Environment]::UserInteractive) {
                    $typed = Read-Host "Type snapshot name '$expectedName' (or '$validId') to confirm deletion"
                    if ($typed -ne $expectedName -and $typed -ne $validId) {
                        throw [System.OperationCanceledException]::new("Snapshot deletion aborted: confirmation text did not match '$expectedName'.")
                    }
                    $confirmHeader = $typed
                }
                else {
                    throw [System.InvalidOperationException]::new("Deleting snapshot '$validId' requires -ConfirmName or -Force in non-interactive sessions.")
                }
            }
        }

        if (-not $Force -and -not $PSCmdlet.ShouldProcess($validId, 'Delete snapshot')) {
            return
        }

        Invoke-InstaboxRequest -Method 'DELETE' -Path "/v1/snapshots/$validId" -RequireIdempotency -IdempotencyKey $IdempotencyKey -ConfirmDelete $confirmHeader | Out-Null
        return [PSCustomObject]@{ Deleted = $true; SnapshotId = $validId }
    }
}

function Get-InstaboxSnapshotFile {
    <#
    .SYNOPSIS
    Reads a directory or UTF-8 text file (<= 256 KiB) from a snapshot's root ext4 system files (GET /v1/snapshots/{id}/files).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('SnapshotId')]
        [string]$Id,

        [Parameter(Position = 1)]
        [string]$Path = '/'
    )

    process {
        $validId = Assert-InstaboxSnapshotId -Id $Id
        $validPath = Assert-InstaboxFilePath -Path $Path
        try {
            $resp = Invoke-InstaboxRequest -Method 'GET' -Path "/v1/snapshots/$validId/files" -Query @{ path = $validPath }
            return $resp.Data
        }
        catch [Instabox.InstaboxApiException] {
            $ex = $_.Exception
            if ($ex.Code -eq 'data_disk_not_browsable') {
                $wrapped = [Instabox.InstaboxApiException]::new("Snapshot file browsing inspects root system files only; '/data' storage is not browsable without starting a sandbox ($($ex.Message))", $ex)
                $wrapped.StatusCode = $ex.StatusCode
                $wrapped.Code = $ex.Code
                $wrapped.RequestId = $ex.RequestId
                $wrapped.Retryable = $ex.Retryable
                $wrapped.DocsUrl = $ex.DocsUrl
                throw $wrapped
            }
            throw
        }
    }
}
