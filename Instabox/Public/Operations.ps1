function Get-InstaboxOperation {
    <#
    .SYNOPSIS
    Gets the current state of an asynchronous operation (GET /v1/operations/{id}).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('OperationId')]
        [string]$Id,

        [string]$WaitDuration
    )

    process {
        $q = @{}
        $timeout = 60
        if (-not [string]::IsNullOrWhiteSpace($WaitDuration)) {
            $q['wait'] = $WaitDuration
            $timeout = 45
        }
        $resp = Invoke-InstaboxRequest -Method 'GET' -Path "/v1/operations/$([Uri]::EscapeDataString($Id))" -Query $q -TimeoutSeconds $timeout
        return $resp.Data
    }
}

function Wait-InstaboxOperation {
    <#
    .SYNOPSIS
    Long-polls GET /v1/operations/{id}?wait=25s until the operation succeeds or fails.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('OperationId')]
        [string]$Id,

        [string]$PollWait = '25s',

        [ValidateRange(1, 7200)]
        [int]$TimeoutSeconds = 600,

        [switch]$Quiet
    )

    process {
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
        try {
            while ($true) {
                $op = Get-InstaboxOperation -Id $Id -WaitDuration $PollWait
                if (-not $Quiet) {
                    $phaseText = if ($op.phase) { " [$($op.phase)]" } else { '' }
                    Write-Progress -Activity "Instabox Operation $Id" -Status "$($op.type): $($op.state)$phaseText"
                }

                if ($op.state -eq 'succeeded') {
                    return $op
                }
                if ($op.state -eq 'failed') {
                    $errJson = if ($op.error) { $op.error | ConvertTo-Json -Depth 10 -Compress } else { '{"code":"internal","message":"Operation failed"}' }
                    $ex = ConvertFrom-InstaboxErrorJson -StatusCode 500 -RawBody $errJson
                    if ([string]::IsNullOrWhiteSpace($ex.OperationId)) {
                        $ex.OperationId = $op.id
                    }
                    throw $ex
                }

                if ([DateTimeOffset]::UtcNow -ge $deadline) {
                    throw [System.TimeoutException]::new("Timed out waiting for operation '$Id' after $TimeoutSeconds seconds (last state: $($op.state), phase: $($op.phase)).")
                }
            }
        }
        finally {
            if (-not $Quiet) {
                Write-Progress -Activity "Instabox Operation $Id" -Completed
            }
        }
    }
}
