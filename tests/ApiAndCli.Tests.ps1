#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:TempHome = Join-Path ([System.IO.Path]::GetTempPath()) ("instabox-int-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:TempHome -Force | Out-Null
    $env:INSTABOX_PS_HOME = $script:TempHome

    . (Join-Path $PSScriptRoot 'MockInstaboxServer.ps1')
    $script:Server = Start-MockInstaboxServer

    Import-Module (Join-Path $script:RepoRoot 'Instabox\Instabox.psd1') -Force
    InModuleScope Instabox { $script:InstaboxSession.RetryDelayScale = 0.01 }
    $null = Set-InstaboxConfig -ApiBaseUrl $script:Server.BaseUrl -ManagedSshConfigPath (Join-Path $script:TempHome 'ssh\instabox_config')
}

AfterAll {
    if ($script:Server) {
        Stop-MockInstaboxServer -Server $script:Server
    }
    if ($script:TempHome -and (Test-Path -LiteralPath $script:TempHome)) {
        Remove-Item -LiteralPath $script:TempHome -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item Env:\INSTABOX_PS_HOME -ErrorAction SilentlyContinue
}

Describe 'Instabox Full 42-Endpoint Integration & CLI Tests' {
    BeforeEach {
        $script:Server.State.Requests.Clear()
    }

    It 'authenticates via Connect-Instabox (GET /v1/me) without rejecting non-52-char keys locally' {
        $res = Connect-Instabox -ApiKey 'ibk_test_personal_key_123456' -BaseUrl $script:Server.BaseUrl
        $res.Login | Should -Be 'riley'
        $res.IsWorkspaceKey | Should -BeFalse
        $me = Get-InstaboxMe
        $me.resizeRestart | Should -BeTrue
        $me.directSecretRefs | Should -BeTrue

        $req = $script:Server.State.Requests[-1]
        $req.Headers['X-API-Key'] | Should -Be 'ibk_test_personal_key_123456'
        [string]::IsNullOrEmpty($req.Headers['Authorization']) | Should -BeTrue
    }

    It 'retries transient 503 errors with Retry-After and retrieves templates (GET /v1/templates)' {
        $script:Server.State.Faults['RetryOnce503'] = 1
        $tmps = Get-InstaboxTemplate -CreatableOnly -LatestOnly
        $tmps.Count | Should -Be 1
        $tmps[0].id | Should -Be 'agent-browser'
        $tmps[0].version | Should -Be '2026-10-15.4'
        ($script:Server.State.Requests | Where-Object { $_.Path -eq '/v1/templates' }).Count | Should -Be 2
    }

    It 'lists sandboxes with pagination and metadata filtering (GET /v1/machines)' {
        $page1 = Get-InstaboxSandbox -PageSize 1 -NoAutoPaginate
        $page1.Machines.Count | Should -Be 1
        $page1.NextCursor | Should -Be '1'

        $all = Get-InstaboxSandbox -PageSize 1
        $all.Count | Should -Be 2

        $filtered = Get-InstaboxSandbox -Metadata @{ env = 'prod' }
        $filtered.Count | Should -Be 1
        $filtered[0].name | Should -Be 'beta-stopped'
    }

    It 'creates, long-polls (?wait=25s), updates (online & apply=restart), controls lifecycle, forks (with fallback), restores, and deletes sandboxes' {
        $mid = 'm_aaaaaaaaaaaaaaaaaaaaaaaaaa'
        $op = New-InstaboxSandbox -Name 'gamma-new' -TemplateId 'agent-browser' -Metadata @{ role = 'ci' } -Wait
        $op.state | Should -Be 'succeeded'
        $op.machine.name | Should -Be 'gamma-new'
        $newId = $op.machineId

        # Verify CreateMachineRequest never sends diskGiB/persistentDiskGiB
        $createReq = $script:Server.State.Requests | Where-Object { $_.Method -eq 'POST' -and $_.Path -eq '/v1/machines' } | Select-Object -Last 1
        $createReq.Headers['Idempotency-Key'] | Should -Not -BeNullOrEmpty
        $createReq.BodyText | Should -Not -Match 'persistentDiskGiB'

        # Verify Wait-InstaboxOperation used ?wait=25s
        $opReq = $script:Server.State.Requests | Where-Object { $_.Path -like '/v1/operations/*' } | Select-Object -First 1
        $opReq.Query['wait'] | Should -Contain '25s'

        # PATCH online grow (200) & apply=restart (202)
        $patched = Update-InstaboxSandbox -Id $newId -Name 'gamma-renamed' -PersistentDiskGiB 40
        $patched.name | Should -Be 'gamma-renamed'
        $patched.spec.persistentDiskGiB | Should -Be 40

        $resOp = Update-InstaboxSandbox -Id $newId -Vcpus 8 -MemMiB 16384 -Apply 'restart' -Wait
        $resOp.type | Should -Be 'resize'
        $resOp.state | Should -Be 'succeeded'

        # Stop, Start (rescue), Suspend, Resume, Wake
        (Stop-InstaboxSandbox -Id $newId -Now -Wait).state | Should -Be 'succeeded'
        (Start-InstaboxSandbox -Id $newId -Rescue -Wait).state | Should -Be 'succeeded'
        (Suspend-InstaboxSandbox -Id $newId -Wait).state | Should -Be 'succeeded'
        (Resume-InstaboxSandbox -Id $newId -DisableVault -Wait).state | Should -Be 'succeeded'
        $woken = Invoke-InstaboxWake -Id $newId
        $woken.state | Should -Be 'running'
        $wakeReq = $script:Server.State.Requests | Where-Object { $_.Path -eq "/v1/machines/$newId/wake" } | Select-Object -Last 1
        [string]::IsNullOrEmpty($wakeReq.Headers['Idempotency-Key']) | Should -BeTrue

        # Fork + 409 fork_unavailable fallback
        $forkOp = Copy-InstaboxSandbox -Id $mid -Name 'alpha-fork' -Wait
        $forkOp.state | Should -Be 'succeeded'

        $script:Server.State.Faults['ForkUnavailable'] = $true
        $fallbackOp = Copy-InstaboxSandbox -Id $mid -Name 'alpha-snap-fork' -FallbackToSnapshot -Wait
        $fallbackOp.state | Should -Be 'succeeded'

        # Restore (also clears known_hosts)
        $kh = Join-Path $script:TempHome 'ssh\known_hosts'
        InModuleScope Instabox -ArgumentList $mid, $kh {
            param($m, $k)
            $null = Set-InstaboxKnownHostsAuthority -MachineId $m -HostName 'ssh.instabox.sh' -Port 2222 -AuthorityPublicKey 'ssh-ed25519 AAAAOLDKEY' -KnownHostsPath $k
        }
        (Restore-InstaboxSandbox -Id $newId -SnapshotId 'sn_aaaaaaaaaaaaaaaaaaaaaaaaaa' -Force -Wait).state | Should -Be 'succeeded'

        # Delete sends X-Confirm-Delete + Idempotency-Key
        (Remove-InstaboxSandbox -Id $newId -ConfirmName 'gamma-renamed' -Now -Wait).state | Should -Be 'succeeded'
        $delReq = $script:Server.State.Requests | Where-Object { $_.Method -eq 'DELETE' -and $_.Path -eq "/v1/machines/$newId" } | Select-Object -Last 1
        $delReq.Headers['X-Confirm-Delete'] | Should -Be 'gamma-renamed'
        $delReq.Headers['Idempotency-Key'] | Should -Not -BeNullOrEmpty
    }

    It 'exercises all file endpoints, resumable Range downloads, signed upload URLs, and exec argv noHistory helpers' {
        $mid = 'm_aaaaaaaaaaaaaaaaaaaaaaaaaa'
        $listing = Get-InstaboxFile -Id $mid -Path '/data/home'
        $listing.type | Should -Be 'dir'

        $localDown = Join-Path $script:TempHome 'large-down.bin'
        $script:Server.State.Faults['TruncateFirstDownload'] = $true
        $dl = Receive-InstaboxFile -Id $mid -RemotePath '/data/home/large.bin' -LocalPath $localDown -Resume
        $dl.Resumed | Should -BeTrue
        $dl.Size | Should -Be 1600

        $upFile = Join-Path $script:TempHome 'upload.txt'
        Set-Content -LiteralPath $upFile -Value 'upload-content-check' -NoNewline -Encoding utf8
        $wr = Send-InstaboxFile -Id $mid -LocalPath $upFile -RemotePath '/data/home/upload.txt' -Mode '0640' -Parents
        $wr.size | Should -Be 20

        # Bare 413 error body parsing
        $script:Server.State.Faults['UploadBare413'] = $true
        { Send-InstaboxFile -Id $mid -Text 'x' -RemotePath '/data/home/fail.txt' } | Should -Throw '*too_large*'

        # Signed Upload URL without API key header
        $uUrl = New-InstaboxUploadUrl -Id $mid -Path '/data/home/signed.txt' -Parents -ExpiresInSeconds 600
        $uUrl.method | Should -Be 'PUT'
        $script:Server.State.Requests.Clear()
        $wrSigned = Send-InstaboxFile -SignedUploadUrl $uUrl.url -LocalPath $upFile
        $wrSigned.created | Should -BeTrue
        $signedPut = $script:Server.State.Requests | Where-Object { $_.Method -eq 'PUT' -and $_.Path -eq "/v1/machines/$mid/files" } | Select-Object -Last 1
        [string]::IsNullOrEmpty($signedPut.Headers['X-API-Key']) | Should -BeTrue

        # mkdir / mv / rm via exec argv + noHistory=true
        $null = New-InstaboxDirectory -Id $mid -Path '/data/home/sub'
        $null = Rename-InstaboxFile -Id $mid -SourcePath '/data/home/a' -DestinationPath '/data/home/b'
        $null = Remove-InstaboxFile -Id $mid -Path '/data/home/b' -Recursive -Force
        $execReqs = @($script:Server.State.Requests | Where-Object { $_.Path -eq "/v1/machines/$mid/exec" })
        $execReqs.Count | Should -Be 3
        foreach ($er in $execReqs) {
            ($er.BodyText | ConvertFrom-Json).noHistory | Should -BeTrue
        }
    }

    It 'exercises SSH tokens, SSH certificates, Enter-InstaboxSandbox, and streaming/keepalive exec' {
        $mid = 'm_aaaaaaaaaaaaaaaaaaaaaaaaaa'
        $mainCfg = Join-Path $script:TempHome 'ssh\main_config'
        $managedCfg = Join-Path $script:TempHome 'ssh\instabox_config'
        $kh = Join-Path $script:TempHome 'ssh\known_hosts'

        $connInfo = Enter-InstaboxSandbox -Id $mid -Mode 'sshToken' -ConfigureOnly -ManagedSshConfigPath $managedCfg -MainSshConfigPath $mainCfg
        $connInfo.Mode | Should -Be 'sshToken'
        $connInfo.VsCodeRemoteUri | Should -Be 'vscode-remote://ssh-remote+instabox-alpha-box/data/home'
        (Get-Content -LiteralPath $managedCfg -Raw) | Should -Match 'PreferredAuthentications none'

        $tokens = Get-InstaboxSshToken -Id $mid
        $tokens.Count | Should -BeGreaterThan 0
        $rev1 = Revoke-InstaboxSshToken -Id $mid -TokenId $tokens[0].id -Force
        $rev1.Revoked | Should -BeTrue

        $null = New-InstaboxSshToken -Id $mid -Name 'extra'
        $revAll = Revoke-InstaboxSshToken -Id $mid -All -Force
        $revAll.revoked | Should -BeGreaterThan 0

        # SSH Cert (uses ssh-keygen if available; pass explicit pubkey fallback if missing)
        if (Get-Command ssh-keygen -ErrorAction SilentlyContinue) {
            $certRes = New-InstaboxSshCertificate -Id $mid -KnownHostsPath $kh
            $certRes.Connection.id | Should -Be 'cn_cert123'
            Test-Path -LiteralPath $certRes.CertificatePath | Should -BeTrue
            (Get-Content -LiteralPath $kh -Raw) | Should -Match '@cert-authority'
        }
        else {
            $certRes = New-InstaboxSshCertificate -Id $mid -PublicKey 'ssh-ed25519 AAAATESTKEY' -KnownHostsPath $kh
            $certRes.Connection.id | Should -Be 'cn_cert123'
        }

        # Streaming SSE exec
        $chunks = [System.Collections.Generic.List[string]]::new()
        $sseRes = Invoke-InstaboxExec -Id $mid -Command 'echo hi' -Stream -OnOutput { param($s, $t) $chunks.Add("${s}:$t") }
        $sseRes.exitCode | Should -Be 0
        $chunks | Should -Contain "stdout:stream-line1`n"

        # Non-streaming keepalive post-200 error + verify NO retry on 503 non-retryable exec
        $script:Server.State.Faults['ExecKeepalivePost200Error'] = $true
        { Invoke-InstaboxExec -Id $mid -Command 'fail-midway' } | Should -Throw '*Lost host mid-command*'

        $script:Server.State.Faults['Exec503NonRetryable'] = $true
        $script:Server.State.Requests.Clear()
        { Invoke-InstaboxExec -Id $mid -Command 'do-not-retry' } | Should -Throw '*Lost host after start*'
        ($script:Server.State.Requests | Where-Object { $_.Path -eq "/v1/machines/$mid/exec" }).Count | Should -Be 1
    }

    It 'exercises public/private HTTP & TCP ports, encrypted port tokens, org/machine Secrets, Snapshots, and Usage' {
        $mid = 'm_aaaaaaaaaaaaaaaaaaaaaaaaaa'
        $orgId = 'org_personal123'

        # Ports
        $pPriv = Publish-InstaboxPort -SandboxId $mid -Port 3000 -Name 'dev-web' -Protocol 'http' -Access 'private'
        $pPriv.token | Should -Match '^ibp_'
        $cachedTok = Get-InstaboxPortToken -PortId $pPriv.id
        $cachedTok.tokenUrl | Should -Be $pPriv.tokenUrl

        $pTcp = Publish-InstaboxPort -SandboxId $mid -Port 5432 -Name 'pg' -Protocol 'tcp'
        $pTcp.url | Should -Match '^tls://'

        (Get-InstaboxPort).ports.Count | Should -Be 2
        (Get-InstaboxPort -SandboxId $mid).ports.Count | Should -Be 2
        $null = Unpublish-InstaboxPort -SandboxId $mid -Port 3000 -Force
        Get-InstaboxPortToken -PortId $pPriv.id | Should -BeNullOrEmpty

        # Secrets
        $envPath = Join-Path $script:TempHome 'import.env'
        Set-Content -LiteralPath $envPath -Value "OPENAI_KEY=sk-test-1`nANTHROPIC_KEY=ak-test-2`n" -Encoding utf8
        $imp = Import-InstaboxOrgSecret -OrgId $orgId -EnvFile $envPath -Delivery 'proxy' -Hosts @('api.openai.com')
        $imp.Count | Should -Be 2

        $secOne = Set-InstaboxOrgSecret -OrgId $orgId -Name 'DB_PASS' -Value 's3cr3t' -Delivery 'env'
        $secOne.delivery | Should -Be 'env'
        (Get-InstaboxOrgSecret -OrgId $orgId).Count | Should -Be 3
        $null = Remove-InstaboxOrgSecret -OrgId $orgId -Name 'DB_PASS' -Force

        $ms = Set-InstaboxSandboxSecret -Id $mid -ProxySecrets @('OPENAI_KEY') -EnvSecrets @()
        $ms.version | Should -Be 2
        $synced = Sync-InstaboxSandboxSecret -Id $mid
        $synced.proxy.state | Should -Be 'applied'
        $syncReq = $script:Server.State.Requests | Where-Object { $_.Method -eq 'POST' -and $_.Path -eq "/v1/machines/$mid/secrets" } | Select-Object -Last 1
        $syncReq.BodyText | Should -BeNullOrEmpty
        [string]::IsNullOrEmpty($syncReq.Headers['Idempotency-Key']) | Should -BeTrue

        # Snapshots
        $sn = New-InstaboxSnapshot -SandboxId $mid -Name 'live-snap' -Wait
        $sn.status | Should -Be 'ready'
        (Get-InstaboxSnapshot).Count | Should -Be 2
        (Get-InstaboxSnapshot -Id $sn.id).id | Should -Be $sn.id

        $sRoot = Get-InstaboxSnapshotFile -Id $sn.id -Path '/'
        $sRoot.type | Should -Be 'dir'
        { Get-InstaboxSnapshotFile -Id $sn.id -Path '/data/home' } | Should -Throw '*root system files only*'

        $null = Remove-InstaboxSnapshot -Id $sn.id -ConfirmName 'live-snap'
        (Get-InstaboxSnapshot).Count | Should -Be 1

        # Usage (unlimited + 80% warning on 170/200 GiB = 85%)
        $usage = Get-InstaboxUsage -OrgId $orgId
        $usage.Summary.MachinesLimit | Should -Be 'Unlimited'
        $usage.Summary.DiskPct | Should -Be 85.0
        ($usage.Summary.Warnings -join ';') | Should -Match '85%'

        # Disconnect revokes tracked SSH tokens
        $disc = Disconnect-Instabox -Confirm:$false
        $disc.SignedOut | Should -BeTrue
    }

    It 'executes instabox.ps1 CLI end-to-end with --json' {
        $cli = Join-Path $script:RepoRoot 'instabox.ps1'
        $null = & pwsh -NoProfile -File $cli --base-url $script:Server.BaseUrl login --key 'ibk_cli_test_key_999' --json
        $LASTEXITCODE | Should -Be 0

        $meJson = & pwsh -NoProfile -File $cli --json me | ConvertFrom-Json
        $meJson.login | Should -Be 'riley'

        $boxesJson = & pwsh -NoProfile -File $cli --json sandboxes list | ConvertFrom-Json
        $boxesJson.Count | Should -BeGreaterThan 0

        $usageJson = & pwsh -NoProfile -File $cli --json usage | ConvertFrom-Json
        $usageJson.Summary.DiskPct | Should -Be 85.0

        $helpOut = & pwsh -NoProfile -File $cli help
        ($helpOut -join "`n") | Should -Match 'instabox PowerShell Application'
    }
}
