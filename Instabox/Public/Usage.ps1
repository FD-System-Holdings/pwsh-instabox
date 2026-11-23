function Get-InstaboxUsage {
    <#
    .SYNOPSIS
    Retrieves sandbox/snapshot/allocated-disk usage, limits (respecting unlimited), and monthly USD cost (GET /v1/usage).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$OrgId
    )

    $q = @{}
    if (-not [string]::IsNullOrWhiteSpace($OrgId)) {
        $q['org'] = $OrgId
    }
    elseif ($cfg = Get-InstaboxConfigInternal) {
        if (-not [string]::IsNullOrWhiteSpace([string]$cfg.DefaultOrg)) {
            $q['org'] = [string]$cfg.DefaultOrg
        }
    }

    $resp = Invoke-InstaboxRequest -Method 'GET' -Path '/v1/usage' -Query $q
    $u = $resp.Data

    $limits = $u.limits
    $unlimited = @()
    if ($limits -and $null -ne $limits.unlimited) {
        $unlimited = @($limits.unlimited | ForEach-Object { [string]$_ })
    }

    $calcMetric = {
        param([double]$used, [int]$limit, [string]$limitName)
        $isUnlimited = ($limitName -in $unlimited)
        $pct = if (-not $isUnlimited -and $limit -gt 0) {
            [Math]::Round(($used / $limit) * 100.0, 1)
        }
        else { $null }
        return [PSCustomObject]@{
            Used      = $used
            Limit     = if ($isUnlimited) { 'Unlimited' } else { $limit }
            Unlimited = $isUnlimited
            Percent   = $pct
        }
    }

    $allocatedDisk = if ($null -ne $u.PSObject.Properties['allocatedDiskGiB'] -and $null -ne $u.allocatedDiskGiB) {
        [double]$u.allocatedDiskGiB
    }
    else { 0.0 }

    $mStat = & $calcMetric ([double]$u.machines) ([int]$limits.maxMachines) 'maxMachines'
    $sStat = & $calcMetric ([double]$u.snapshots) ([int]$limits.maxSnapshots) 'maxSnapshots'
    $dStat = & $calcMetric $allocatedDisk ([int]$limits.maxStoredGiB) 'maxStoredGiB'

    $warnings = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $mStat.Percent -and $mStat.Percent -ge 80.0) {
        $warnings.Add("Sandboxes at $($mStat.Percent)% ($($mStat.Used)/$($mStat.Limit))")
    }
    if ($null -ne $sStat.Percent -and $sStat.Percent -ge 80.0) {
        $warnings.Add("Snapshots at $($sStat.Percent)% ($($sStat.Used)/$($sStat.Limit))")
    }
    if ($null -ne $dStat.Percent -and $dStat.Percent -ge 80.0) {
        $warnings.Add("Allocated disk at $($dStat.Percent)% ($($dStat.Used)/$($dStat.Limit) GiB)")
    }

    $summary = [PSCustomObject]@{
        Org             = $u.org
        MachinesUsed    = $u.machines
        MachinesLimit   = $mStat.Limit
        MachinesPct     = $mStat.Percent
        SnapshotsUsed   = $u.snapshots
        SnapshotsLimit  = $sStat.Limit
        SnapshotsPct    = $sStat.Percent
        AllocatedDiskGiB = $allocatedDisk
        DiskLimitGiB    = $dStat.Limit
        DiskPct         = $dStat.Percent
        CostUSD         = if ($u.cost) { $u.cost.costUSD } else { $null }
        AllowanceUSD    = if ($u.cost) { $u.cost.allowanceUSD } else { $null }
        CreditLeftUSD   = if ($u.cost) { $u.cost.creditRemainingUSD } else { $null }
        CreditsUSD      = if ($u.cost) { $u.cost.creditsUSD } else { $null }
        Warnings        = $warnings.ToArray()
    }

    $u | Add-Member -NotePropertyName 'Summary' -NotePropertyValue $summary -Force
    return $u
}
