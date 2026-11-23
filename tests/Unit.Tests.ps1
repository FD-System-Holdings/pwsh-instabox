#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:TempHome = Join-Path ([System.IO.Path]::GetTempPath()) ("instabox-unit-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:TempHome -Force | Out-Null
    $env:INSTABOX_PS_HOME = $script:TempHome

    Import-Module (Join-Path $script:RepoRoot 'Instabox\Instabox.psd1') -Force
}

AfterAll {
    if ($script:TempHome -and (Test-Path -LiteralPath $script:TempHome)) {
        Remove-Item -LiteralPath $script:TempHome -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item Env:\INSTABOX_PS_HOME -ErrorAction SilentlyContinue
}

Describe 'Instabox Private Unit Tests' {
    It 'validates canonical machine IDs and snapshot IDs' {
        InModuleScope Instabox {
            $m = 'm_' + ('a' * 26)
            Assert-InstaboxMachineId -Id $m | Should -Be $m
            { Assert-InstaboxMachineId -Id 'my-box-name' } | Should -Throw
            { Assert-InstaboxMachineId -Id 'm_UPPERCASE' } | Should -Throw

            $sn = 'sn_' + ('b' * 26)
            $im = 'im_' + ('2' * 26)
            Assert-InstaboxSnapshotId -Id $sn | Should -Be $sn
            Assert-InstaboxSnapshotId -Id $im | Should -Be $im
            { Assert-InstaboxSnapshotId -Id 'bad_123' } | Should -Throw
        }
    }

    It 'validates secret names, reserved vars, hosts, values, ports, metadata, and safe HTTPS URLs' {
        InModuleScope Instabox {
            Assert-InstaboxSecretName -Name 'OPENAI_API_KEY' | Should -Be 'OPENAI_API_KEY'
            { Assert-InstaboxSecretName -Name 'PATH' } | Should -Throw
            { Assert-InstaboxSecretName -Name 'INSTABOX_TOKEN' } | Should -Throw
            { Assert-InstaboxSecretName -Name 'SSH_AUTH_SOCK' } | Should -Throw
            { Assert-InstaboxGuestUser -GuestUser 'root' } | Should -Throw
            { Assert-InstaboxGuestUser -GuestUser 'systemd-network' } | Should -Throw
            Assert-InstaboxGuestUser -GuestUser 'alice_1' | Should -Be 'alice_1'

            Assert-InstaboxSecretHosts -Delivery 'proxy' -Hosts @('API.OpenAI.com', '*') | Should -Be @('api.openai.com', '*')
            { Assert-InstaboxSecretHosts -Delivery 'proxy' -Hosts @() } | Should -Throw
            { Assert-InstaboxSecretHosts -Delivery 'proxy' -Hosts @('https://api.openai.com') } | Should -Throw
            { Assert-InstaboxSecretHosts -Delivery 'proxy' -Hosts @('*.openai.com') } | Should -Throw
            { Assert-InstaboxSecretHosts -Delivery 'proxy' -Hosts @('127.0.0.1') } | Should -Throw
            { Assert-InstaboxSecretHosts -Delivery 'proxy' -Hosts @('localhost') } | Should -Throw
            { Assert-InstaboxSecretHosts -Delivery 'env' -Hosts @('api.openai.com') } | Should -Throw

            { Assert-InstaboxSecretValue -Delivery 'proxy' -Value "bad`nvalue" } | Should -Throw
            Assert-InstaboxSecretValue -Delivery 'env' -Value "multi`nline" | Should -Be "multi`nline"

            Assert-InstaboxPort -Port 3000 | Should -Be 3000
            { Assert-InstaboxPort -Port 80 } | Should -Throw
            { Assert-InstaboxPort -Port 5901 } | Should -Throw
            { Assert-InstaboxPort -Port 6768 } | Should -Throw

            Test-InstaboxSafeHttpsUrl -Url 'https://instabox.sh/docs/errors' | Should -BeTrue
            Test-InstaboxSafeHttpsUrl -Url 'javascript:alert(1)' | Should -BeFalse
        }
    }

    It 'parses .env files with comments, export prefixes, quotes, and escapes' {
        InModuleScope Instabox {
            $raw = @"
# comment line
export API_KEY=sk-123 # trailing comment
DOUBLE="hello\nworld" # inline
SINGLE='raw # not comment \n'
EMPTY=
"@
            $map = ConvertFrom-InstaboxDotEnv -Content $raw
            $map['API_KEY'] | Should -Be 'sk-123'
            $map['DOUBLE'] | Should -Be "hello`nworld"
            $map['SINGLE'] | Should -Be 'raw # not comment \n'
            $map['EMPTY'] | Should -Be ''
        }
    }

    It 'redacts sensitive tokens, headers, and query params from logs' {
        InModuleScope Instabox {
            $sample = 'X-API-Key: ibk_secret123 Authorization: Bearer iba_tok456 ssh=ibssh_abc789 tokenUrl=https://x.sh/?_token=ibp_port999&token=signed_abc'
            $safe = Protect-InstaboxLogText -Text $sample
            $safe | Should -Not -Match 'secret123'
            $safe | Should -Not -Match 'tok456'
            $safe | Should -Not -Match 'abc789'
            $safe | Should -Not -Match 'port999'
            $safe | Should -Not -Match 'signed_abc'
            $safe | Should -Match '\[REDACTED\]'
        }
    }

    It 'stores and retrieves encrypted secrets in isolated INSTABOX_PS_HOME' {
        InModuleScope Instabox {
            Set-InstaboxSecretValue -Name 'testSecret' -Value 'super-secret-value'
            Get-InstaboxSecretValue -Name 'testSecret' | Should -Be 'super-secret-value'
            $rawFile = Get-Content -LiteralPath (Join-Path (Get-InstaboxStateDir) 'secrets.json') -Raw
            $rawFile | Should -Not -Match 'super-secret-value'
            Remove-InstaboxSecretValue -Name 'testSecret'
            Get-InstaboxSecretValue -Name 'testSecret' | Should -BeNullOrEmpty
        }
    }

    It 'manages ~/.ssh/instabox_config blocks by machineId without touching user blocks and purges known_hosts on restore' {
        InModuleScope Instabox {
            $sshDir = Join-Path $env:INSTABOX_PS_HOME 'ssh'
            $mainCfg = Join-Path $sshDir 'config'
            $managedCfg = Join-Path $sshDir 'instabox_config'
            $kh = Join-Path $sshDir 'known_hosts'

            New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
            Set-Content -LiteralPath $mainCfg -Value "Host my-custom-server`n    HostName 10.0.0.1`n" -Encoding utf8

            $mid = 'm_' + ('a' * 26)
            $null = Set-InstaboxSshHostBlock -MachineId $mid -SandboxName 'box-one' -HostName 'ssh.instabox.sh' -Port 2222 -User 'ibssh_abc' -UseNoneAuth -ManagedConfigPath $managedCfg -MainSshConfigPath $mainCfg
            $mainText = Get-Content -LiteralPath $mainCfg -Raw
            $mainText | Should -Match 'Host my-custom-server'
            $mainText | Should -Match 'Include '

            # Rename sandbox: block should replace cleanly in place
            $null = Set-InstaboxSshHostBlock -MachineId $mid -SandboxName 'box-renamed' -HostName 'ssh.instabox.sh' -Port 2222 -User 'ibssh_def' -UseNoneAuth -ManagedConfigPath $managedCfg -MainSshConfigPath $mainCfg
            $mgText = Get-Content -LiteralPath $managedCfg -Raw
            $mgText | Should -Match 'instabox-box-renamed'
            $mgText | Should -Not -Match 'instabox-box-one'

            # CA known_hosts write & purge
            $null = Set-InstaboxKnownHostsAuthority -MachineId $mid -HostName 'ssh.instabox.sh' -Port 2222 -AuthorityPublicKey 'ssh-ed25519 AAAATESTCA' -KnownHostsPath $kh
            (Get-Content -LiteralPath $kh -Raw) | Should -Match '@cert-authority \[ssh\.instabox\.sh\]:2222'
            Clear-InstaboxKnownHostsEntry -MachineId $mid -KnownHostsPath $kh
            (Get-Content -LiteralPath $kh -Raw) | Should -BeNullOrEmpty

            Remove-InstaboxSshHostBlock -MachineId $mid -ManagedConfigPath $managedCfg
            (Get-Content -LiteralPath $managedCfg -Raw) | Should -Not -Match $mid
        }
    }

    It 'parses standard ErrorBody, bare Error, and post-200 keepalive error envelopes' {
        InModuleScope Instabox {
            $ex1 = ConvertFrom-InstaboxErrorJson -StatusCode 403 -RawBody '{"error":{"code":"missing_scope","message":"Missing scope","requestId":"req_1","retryable":false,"operationId":null,"requiredScopes":["machines:write"]}}'
            $ex1.Code | Should -Be 'missing_scope'
            $ex1.RequiredScopes | Should -Contain 'machines:write'

            $ex2 = ConvertFrom-InstaboxErrorJson -StatusCode 413 -RawBody '{"code":"too_large","message":"Too large","requestId":"req_2","retryable":false,"operationId":null}'
            $ex2.StatusCode | Should -Be 413
            $ex2.Code | Should -Be 'too_large'

            $ex3 = ConvertFrom-InstaboxErrorJson -StatusCode 200 -RawBody '{"error":{"code":"host_unavailable","message":"Lost host","requestId":"req_3","retryable":false,"operationId":null},"status":503}'
            $ex3.StatusCode | Should -Be 503
            $ex3.Code | Should -Be 'host_unavailable'
        }
    }
}
