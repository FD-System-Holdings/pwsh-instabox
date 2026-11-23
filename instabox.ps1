#!/usr/bin/env pwsh
<#
.SYNOPSIS
instabox PowerShell CLI & Interactive Console Application (covering all 42 documented REST endpoints).
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments)]
    [string[]]$CliArgs
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Instabox\Instabox.psd1') -Force

$jsonOutput = $false
$rawArgs = [System.Collections.Generic.List[string]]::new()
$i = 0
while ($i -lt ($CliArgs ? $CliArgs.Count : 0)) {
    $a = $CliArgs[$i]
    if ($a -eq '--json') {
        $jsonOutput = $true
        $i++
        continue
    }
    if ($a -eq '--base-url' -and ($i + 1) -lt $CliArgs.Count) {
        Set-InstaboxConfig -ApiBaseUrl $CliArgs[$i + 1] | Out-Null
        $i += 2
        continue
    }
    $rawArgs.Add($a)
    $i++
}

function Format-CliOutput {
    param($Data, [switch]$AsJson)
    if ($null -eq $Data) { return }
    if ($AsJson) {
        $Data | ConvertTo-Json -Depth 15
    }
    else {
        $Data
    }
}

function Parse-FlagMap {
    param([string[]]$Tokens)
    $flags = @{}
    $pos = [System.Collections.Generic.List[string]]::new()
    $idx = 0
    while ($idx -lt $Tokens.Count) {
        $t = $Tokens[$idx]
        if ($t -eq '--') {
            for ($j = $idx + 1; $j -lt $Tokens.Count; $j++) { $pos.Add($Tokens[$j]) }
            break
        }
        if ($t.StartsWith('--')) {
            $name = $t.Substring(2)
            if (($idx + 1) -lt $Tokens.Count -and -not $Tokens[$idx + 1].StartsWith('--')) {
                $val = $Tokens[$idx + 1]
                if ($flags.ContainsKey($name)) {
                    $flags[$name] = @($flags[$name]) + @($val)
                }
                else {
                    $flags[$name] = $val
                }
                $idx += 2
            }
            else {
                $flags[$name] = $true
                $idx++
            }
        }
        else {
            $pos.Add($t)
            $idx++
        }
    }
    return [PSCustomObject]@{ Flags = $flags; Positional = $pos.ToArray() }
}

$helpText = @'
instabox PowerShell Application (pwsh 7+)

Usage:
  ./instabox.ps1 [--json] [--base-url URL] <command> [subcommand] [args...]

Commands:
  ui                                    Launch interactive console dashboard
  login [--key IBK_...]                 Verify & store API key via GET /v1/me
  logout [--keep-tokens]                Sign out & revoke extension-tracked SSH tokens
  me                                    Show GET /v1/me profile, orgs & capabilities
  templates [--all]                     List creatable templates (GET /v1/templates)
  sandboxes list|get|create|start|stop|pause|resume|wake|rename|resize|fork|restore|rm
  ops get|wait <opId>                   Inspect or long-poll (?wait=25s) an operation
  exec <machineId> --cmd "..."          Run command (add --stream for SSE)
  ssh <machineId> [--mode sshToken|sshCert|terminal] [--configure-only]
  tokens list|create|revoke <machineId> Manage SSH tokens
  files ls|cat|get|put|upload-url|mkdir|mv|rm
  ports list|expose|unpublish|token
  secrets org-list|org-set|org-rm|org-import|box-get|box-set|box-sync
  snapshots list|get|save|files|rm
  usage [--org org_...]                 Show live allocatedDiskGiB, limits & monthly cost
  version                               Show application version
  help                                  Show this help
'@

if ($rawArgs.Count -eq 0) {
    Start-InstaboxApp
    return
}

$cmd = $rawArgs[0].ToLowerInvariant()
$rest = if ($rawArgs.Count -gt 1) { $rawArgs.GetRange(1, $rawArgs.Count - 1).ToArray() } else { @() }
$parsed = Parse-FlagMap -Tokens $rest
$f = $parsed.Flags
$p = $parsed.Positional

try {
    switch ($cmd) {
        { $_ -in @('help', '--help', '-h') } {
            Write-Output $helpText
        }
        'version' {
            Format-CliOutput ([PSCustomObject]@{ Name = 'instabox-pwsh'; Version = '0.1.0'; PowerShell = $PSVersionTable.PSVersion.ToString() }) -AsJson:$jsonOutput
        }
        'ui' {
            Start-InstaboxApp
        }
        'login' {
            $res = if ($f.ContainsKey('key')) { Connect-Instabox -ApiKey ([string]$f['key']) } else { Connect-Instabox }
            Format-CliOutput $res -AsJson:$jsonOutput
        }
        'logout' {
            $res = Disconnect-Instabox -KeepSshTokens:([bool]$f['keep-tokens']) -Confirm:$false
            Format-CliOutput $res -AsJson:$jsonOutput
        }
        'me' {
            Format-CliOutput (Get-InstaboxMe) -AsJson:$jsonOutput
        }
        'templates' {
            $all = [bool]$f['all']
            Format-CliOutput (Get-InstaboxTemplate -CreatableOnly:(-not $all) -LatestOnly:(-not $all)) -AsJson:$jsonOutput
        }
        'ops' {
            $sub = if ($p.Count -ge 1) { $p[0] } else { throw 'Missing subcommand (get|wait)' }
            $id = if ($p.Count -ge 2) { $p[1] } else { throw 'Missing operation ID' }
            if ($sub -eq 'wait') {
                Format-CliOutput (Wait-InstaboxOperation -Id $id) -AsJson:$jsonOutput
            }
            else {
                Format-CliOutput (Get-InstaboxOperation -Id $id) -AsJson:$jsonOutput
            }
        }
        'sandboxes' {
            $sub = if ($p.Count -ge 1) { $p[0] } else { 'list' }
            switch ($sub) {
                'list' { Format-CliOutput (Get-InstaboxSandbox) -AsJson:$jsonOutput }
                'get' { Format-CliOutput (Get-InstaboxSandbox -Id $p[1]) -AsJson:$jsonOutput }
                'create' {
                    $argsMap = @{ Wait = [bool]$f['wait'] }
                    if ($f['name']) { $argsMap['Name'] = [string]$f['name'] }
                    if ($f['template']) { $argsMap['TemplateId'] = [string]$f['template'] }
                    if ($f['snapshot']) { $argsMap['SnapshotId'] = [string]$f['snapshot'] }
                    if ($f['vcpus']) { $argsMap['Vcpus'] = [int]$f['vcpus'] }
                    if ($f['mem']) { $argsMap['MemMiB'] = [int]$f['mem'] }
                    if ($f['org']) { $argsMap['OrgId'] = [string]$f['org'] }
                    if ($f['fail-fast']) { $argsMap['FailFast'] = $true }
                    if ($f['accept-minimum-lease']) { $argsMap['AcceptMinimumLease'] = $true }
                    Format-CliOutput (New-InstaboxSandbox @argsMap) -AsJson:$jsonOutput
                }
                'start' { Format-CliOutput (Start-InstaboxSandbox -Id $p[1] -Rescue:([bool]$f['rescue']) -Wait:([bool]$f['wait'])) -AsJson:$jsonOutput }
                'stop' { Format-CliOutput (Stop-InstaboxSandbox -Id $p[1] -Now:([bool]$f['now']) -Wait:([bool]$f['wait'])) -AsJson:$jsonOutput }
                'pause' { Format-CliOutput (Suspend-InstaboxSandbox -Id $p[1] -Wait:([bool]$f['wait'])) -AsJson:$jsonOutput }
                'resume' { Format-CliOutput (Resume-InstaboxSandbox -Id $p[1] -Wait:([bool]$f['wait'])) -AsJson:$jsonOutput }
                'wake' { Format-CliOutput (Invoke-InstaboxWake -Id $p[1]) -AsJson:$jsonOutput }
                'rename' { Format-CliOutput (Update-InstaboxSandbox -Id $p[1] -Name $p[2]) -AsJson:$jsonOutput }
                'resize' {
                    $argsMap = @{ Id = $p[1]; Wait = [bool]$f['wait'] }
                    if ($f['disk']) { $argsMap['PersistentDiskGiB'] = [int]$f['disk'] }
                    if ($f['vcpus']) { $argsMap['Vcpus'] = [int]$f['vcpus'] }
                    if ($f['mem']) { $argsMap['MemMiB'] = [int]$f['mem'] }
                    if ($f['restart']) { $argsMap['Apply'] = 'restart' }
                    Format-CliOutput (Update-InstaboxSandbox @argsMap) -AsJson:$jsonOutput
                }
                'fork' {
                    $argsMap = @{ Id = $p[1]; Wait = [bool]$f['wait']; FallbackToSnapshot = [bool]$f['fallback-snapshot'] }
                    if ($f['name']) { $argsMap['Name'] = [string]$f['name'] }
                    Format-CliOutput (Copy-InstaboxSandbox @argsMap) -AsJson:$jsonOutput
                }
                'restore' {
                    $argsMap = @{ Id = $p[1]; Force = $true; Wait = [bool]$f['wait'] }
                    if ($f['snapshot']) { $argsMap['SnapshotId'] = [string]$f['snapshot'] }
                    Format-CliOutput (Restore-InstaboxSandbox @argsMap) -AsJson:$jsonOutput
                }
                'rm' {
                    $argsMap = @{ Id = $p[1]; Force = [bool]$f['force']; Now = [bool]$f['now']; Wait = [bool]$f['wait'] }
                    if ($f['confirm']) { $argsMap['ConfirmName'] = [string]$f['confirm'] }
                    Format-CliOutput (Remove-InstaboxSandbox @argsMap) -AsJson:$jsonOutput
                }
                default { throw "Unknown sandboxes subcommand '$sub'." }
            }
        }
        'exec' {
            $id = $p[0]
            $argsMap = @{ Id = $id; Stream = [bool]$f['stream']; NoHistory = [bool]$f['no-history'] }
            if ($f['cwd']) { $argsMap['Cwd'] = [string]$f['cwd'] }
            if ($f['timeout']) { $argsMap['TimeoutSeconds'] = [int]$f['timeout'] }
            if ($f['cmd']) {
                $argsMap['Command'] = [string]$f['cmd']
            }
            elseif ($p.Count -gt 1) {
                $argsMap['Argv'] = [string[]]$p[1..($p.Count - 1)]
            }
            else {
                throw "Provide --cmd '...' or argv arguments after machineId."
            }
            Format-CliOutput (Invoke-InstaboxExec @argsMap) -AsJson:$jsonOutput
        }
        'ssh' {
            $argsMap = @{ Id = $p[0]; ConfigureOnly = [bool]$f['configure-only']; Mosh = [bool]$f['mosh'] }
            if ($f['mode']) { $argsMap['Mode'] = [string]$f['mode'] }
            Format-CliOutput (Enter-InstaboxSandbox @argsMap) -AsJson:$jsonOutput
        }
        'tokens' {
            $sub = $p[0]
            $id = $p[1]
            switch ($sub) {
                'list' { Format-CliOutput (Get-InstaboxSshToken -Id $id) -AsJson:$jsonOutput }
                'create' { Format-CliOutput (New-InstaboxSshToken -Id $id -Name ([string]($f['name'] ?? 'instabox-ps'))) -AsJson:$jsonOutput }
                'revoke' {
                    if ($f['all']) { Format-CliOutput (Revoke-InstaboxSshToken -Id $id -All -Force) -AsJson:$jsonOutput }
                    else { Format-CliOutput (Revoke-InstaboxSshToken -Id $id -TokenId $p[2] -Force) -AsJson:$jsonOutput }
                }
                default { throw "Unknown tokens subcommand '$sub'." }
            }
        }
        'files' {
            $sub = $p[0]
            $id = $p[1]
            switch ($sub) {
                'ls' { Format-CliOutput (Get-InstaboxFile -Id $id -Path ($p.Count -gt 2 ? $p[2] : '/')) -AsJson:$jsonOutput }
                'cat' { Format-CliOutput (Get-InstaboxFile -Id $id -Path $p[2]) -AsJson:$jsonOutput }
                'get' { Format-CliOutput (Receive-InstaboxFile -Id $id -RemotePath $p[2] -LocalPath $p[3] -Resume:([bool]$f['resume'])) -AsJson:$jsonOutput }
                'put' { Format-CliOutput (Send-InstaboxFile -Id $id -LocalPath $p[2] -RemotePath $p[3] -Parents:([bool]$f['parents'])) -AsJson:$jsonOutput }
                'upload-url' { Format-CliOutput (New-InstaboxUploadUrl -Id $id -Path $p[2] -Parents:([bool]$f['parents'])) -AsJson:$jsonOutput }
                'mkdir' { Format-CliOutput (New-InstaboxDirectory -Id $id -Path $p[2]) -AsJson:$jsonOutput }
                'mv' { Format-CliOutput (Rename-InstaboxFile -Id $id -SourcePath $p[2] -DestinationPath $p[3] -Force:([bool]$f['force'])) -AsJson:$jsonOutput }
                'rm' { Format-CliOutput (Remove-InstaboxFile -Id $id -Path $p[2] -Recursive:([bool]$f['recursive']) -Force) -AsJson:$jsonOutput }
                default { throw "Unknown files subcommand '$sub'." }
            }
        }
        'ports' {
            $sub = $p.Count -ge 1 ? $p[0] : 'list'
            switch ($sub) {
                'list' {
                    if ($p.Count -ge 2) { Format-CliOutput (Get-InstaboxPort -SandboxId $p[1]) -AsJson:$jsonOutput }
                    else { Format-CliOutput (Get-InstaboxPort) -AsJson:$jsonOutput }
                }
                'expose' {
                    $argsMap = @{ SandboxId = $p[1]; Port = [int]$p[2]; RotateToken = [bool]$f['rotate-token'] }
                    if ($f['name']) { $argsMap['Name'] = [string]$f['name'] }
                    if ($f['protocol']) { $argsMap['Protocol'] = [string]$f['protocol'] }
                    if ($f['access']) { $argsMap['Access'] = [string]$f['access'] }
                    Format-CliOutput (Publish-InstaboxPort @argsMap) -AsJson:$jsonOutput
                }
                'unpublish' { Format-CliOutput (Unpublish-InstaboxPort -SandboxId $p[1] -Port ([int]$p[2]) -Force) -AsJson:$jsonOutput }
                'token' { Format-CliOutput (Get-InstaboxPortToken -PortId $p[1]) -AsJson:$jsonOutput }
                default { throw "Unknown ports subcommand '$sub'." }
            }
        }
        'secrets' {
            $sub = $p[0]
            switch ($sub) {
                'org-list' { Format-CliOutput (Get-InstaboxOrgSecret -OrgId $p[1]) -AsJson:$jsonOutput }
                'org-set' {
                    $hosts = if ($f['hosts']) { @([string]$f['hosts'] -split ',') } else { @() }
                    Format-CliOutput (Set-InstaboxOrgSecret -OrgId $p[1] -Name $p[2] -Value $p[3] -Delivery ([string]$f['delivery']) -Hosts $hosts) -AsJson:$jsonOutput
                }
                'org-rm' { Format-CliOutput (Remove-InstaboxOrgSecret -OrgId $p[1] -Name $p[2] -Force) -AsJson:$jsonOutput }
                'org-import' {
                    $hosts = if ($f['hosts']) { @([string]$f['hosts'] -split ',') } else { @() }
                    Format-CliOutput (Import-InstaboxOrgSecret -OrgId $p[1] -EnvFile $p[2] -Delivery ([string]$f['delivery']) -Hosts $hosts) -AsJson:$jsonOutput
                }
                'box-get' { Format-CliOutput (Get-InstaboxSandboxSecret -Id $p[1]) -AsJson:$jsonOutput }
                'box-set' {
                    $argsMap = @{ Id = $p[1] }
                    if ($f['proxy']) { $argsMap['ProxySecrets'] = ($f['proxy'] -eq 'all') ? 'all' : @([string]$f['proxy'] -split ',' | Where-Object { $_ }) }
                    if ($f['env']) { $argsMap['EnvSecrets'] = @([string]$f['env'] -split ',' | Where-Object { $_ }) }
                    Format-CliOutput (Set-InstaboxSandboxSecret @argsMap) -AsJson:$jsonOutput
                }
                'box-sync' { Format-CliOutput (Sync-InstaboxSandboxSecret -Id $p[1]) -AsJson:$jsonOutput }
                default { throw "Unknown secrets subcommand '$sub'." }
            }
        }
        'snapshots' {
            $sub = $p.Count -ge 1 ? $p[0] : 'list'
            switch ($sub) {
                'list' { Format-CliOutput (Get-InstaboxSnapshot) -AsJson:$jsonOutput }
                'get' { Format-CliOutput (Get-InstaboxSnapshot -Id $p[1]) -AsJson:$jsonOutput }
                'save' {
                    Format-CliOutput (New-InstaboxSnapshot -SandboxId $p[1] -Name $p[2] -RootOnly:([bool]$f['root-only']) -ForFork:([bool]$f['for-fork']) -Wait:([bool]$f['wait'])) -AsJson:$jsonOutput
                }
                'files' { Format-CliOutput (Get-InstaboxSnapshotFile -Id $p[1] -Path ($p.Count -gt 2 ? $p[2] : '/')) -AsJson:$jsonOutput }
                'rm' { Format-CliOutput (Remove-InstaboxSnapshot -Id $p[1] -ConfirmName ([string]$f['confirm']) -Force:([bool]$f['force'])) -AsJson:$jsonOutput }
                default { throw "Unknown snapshots subcommand '$sub'." }
            }
        }
        'usage' {
            Format-CliOutput (Get-InstaboxUsage -OrgId ([string]$f['org'])) -AsJson:$jsonOutput
        }
        default {
            throw "Unknown command '$cmd'. Run './instabox.ps1 help' for usage."
        }
    }
}
catch [Instabox.InstaboxApiException] {
    $ex = $_.Exception
    if ($jsonOutput) {
        [PSCustomObject]@{
            error = [PSCustomObject]@{
                statusCode        = $ex.StatusCode
                code              = $ex.Code
                message           = $ex.Message
                requestId         = $ex.RequestId
                retryable         = $ex.Retryable
                operationId       = $ex.OperationId
                reason            = $ex.Reason
                hint              = $ex.Hint
                requiredScopes    = $ex.RequiredScopes
                retryAfterSeconds = $ex.RetryAfterSeconds
            }
        } | ConvertTo-Json -Depth 10
    }
    else {
        Write-Error "Instabox API Error ($($ex.StatusCode) $($ex.Code)): $($ex.Message) [requestId=$($ex.RequestId)]"
    }
    exit 1
}
