function Start-MockInstaboxServer {
    [CmdletBinding()]
    param()

    $tcp = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $tcp.Start()
    $port = ([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port
    $tcp.Stop()

    $baseUrl = "http://127.0.0.1:$port"

    $state = [hashtable]::Synchronized(@{
        BaseUrl           = $baseUrl
        Requests          = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
        Machines          = [hashtable]::Synchronized(@{
            'm_aaaaaaaaaaaaaaaaaaaaaaaaaa' = [ordered]@{
                id                      = 'm_aaaaaaaaaaaaaaaaaaaaaaaaaa'
                name                    = 'alpha-box'
                desiredState            = 'running'
                state                   = 'running'
                revision                = 1
                operationId             = $null
                template                = @{ id = 'agent-browser'; version = '2026-10-15.4'; digest = 'sha256:111' }
                spec                    = @{ vcpus = 4; memMiB = 8192; persistentDiskGiB = 20 }
                storage                 = @{ sizeGiB = 20; mountPath = '/data'; persistent = $true; synced = $true }
                runtime                 = @{ ready = $true }
                autoSuspendAfterSeconds = 1800
                maxRunMinutes           = 120
                runStartedAt            = '2026-11-20T00:00:00Z'
                cooldownUntil           = $null
                metadata                = @{ env = 'dev' }
                vault                   = $true
                guestUser               = 'dev'
                orgId                   = 'org_personal123'
                createdAt               = '2026-11-20T00:00:00Z'
                updatedAt               = '2026-11-20T00:00:00Z'
            }
            'm_bbbbbbbbbbbbbbbbbbbbbbbbbb' = [ordered]@{
                id                      = 'm_bbbbbbbbbbbbbbbbbbbbbbbbbb'
                name                    = 'beta-stopped'
                desiredState            = 'stopped'
                state                   = 'stopped'
                revision                = 2
                operationId             = $null
                template                = @{ id = 'omarchy'; version = '2026-10-10.1'; digest = 'sha256:222' }
                spec                    = @{ vcpus = 4; memMiB = 8192; persistentDiskGiB = 20 }
                storage                 = @{ sizeGiB = 20; mountPath = '/data'; persistent = $true; synced = $true }
                runtime                 = @{ ready = $false }
                autoSuspendAfterSeconds = 1800
                maxRunMinutes           = -1
                runStartedAt            = $null
                cooldownUntil           = $null
                metadata                = @{ env = 'prod' }
                vault                   = $true
                guestUser               = 'dev'
                orgId                   = 'org_work456'
                createdAt               = '2026-11-20T00:00:00Z'
                updatedAt               = '2026-11-20T00:00:00Z'
            }
        })
        Operations        = [hashtable]::Synchronized(@{})
        OpPollCount       = [hashtable]::Synchronized(@{})
        Snapshots         = [hashtable]::Synchronized(@{
            'sn_aaaaaaaaaaaaaaaaaaaaaaaaaa' = [ordered]@{
                id                = 'sn_aaaaaaaaaaaaaaaaaaaaaaaaaa'
                name              = 'base-snap'
                orgId             = 'org_personal123'
                sourceMachineId   = 'm_aaaaaaaaaaaaaaaaaaaaaaaaaa'
                sourceSnapshotSeq = 1
                status            = 'ready'
                template          = @{ id = 'agent-browser'; version = '2026-10-15.4'; digest = 'sha256:111' }
                rootSizeBytes     = 10737418240
                dataSizeBytes     = 21474836480
                sizeLocked        = $true
                defaultSpec       = @{ vcpus = 4; memMiB = 8192; persistentDiskGiB = 20 }
                createdAt         = '2026-11-20T00:00:00Z'
            }
        })
        SnapPollCount     = [hashtable]::Synchronized(@{})
        Ports             = [hashtable]::Synchronized(@{})
        OrgSecrets        = [hashtable]::Synchronized(@{})
        MachineSecrets    = [hashtable]::Synchronized(@{})
        SshTokens         = [hashtable]::Synchronized(@{})
        Files             = [hashtable]::Synchronized(@{
            'm_aaaaaaaaaaaaaaaaaaaaaaaaaa:/data/home/hello.txt' = [System.Text.Encoding]::UTF8.GetBytes('Hello from Instabox!')
            'm_aaaaaaaaaaaaaaaaaaaaaaaaaa:/data/home/large.bin' = [System.Text.Encoding]::UTF8.GetBytes(('0123456789ABCDEF' * 100))
        })
        FileEtags         = [hashtable]::Synchronized(@{
            'm_aaaaaaaaaaaaaaaaaaaaaaaaaa:/data/home/large.bin' = '"etag-v1"'
        })
        Faults            = [hashtable]::Synchronized(@{})
    })

    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("$baseUrl/")
    $listener.Start()

    $ps = [powershell]::Create()
    $null = $ps.AddScript({
        param($listener, $state)

        function Send-Json($ctx, [int]$status, $obj, [hashtable]$headers = $null) {
            $resp = $ctx.Response
            $resp.StatusCode = $status
            if ($headers) {
                foreach ($hk in $headers.Keys) {
                    $resp.Headers.Add([string]$hk, [string]$headers[$hk])
                }
            }
            if ($status -eq 204) {
                $resp.Close()
                return
            }
            $resp.ContentType = 'application/json; charset=utf-8'
            $json = if ($obj -is [string]) { $obj } else { $obj | ConvertTo-Json -Depth 15 -Compress }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $resp.ContentLength64 = $bytes.Length
            $resp.OutputStream.Write($bytes, 0, $bytes.Length)
            $resp.Close()
        }

        function Send-Err($ctx, [int]$status, [string]$code, [string]$message, [bool]$retryable = $false, [int]$retryAfter = 0, [string]$opId = $null, [string]$reason = $null, [string[]]$scopes = $null) {
            $err = [ordered]@{
                code        = $code
                message     = $message
                requestId   = 'req_mock_' + ([guid]::NewGuid().ToString('N').Substring(0, 10))
                retryable   = $retryable
                operationId = $opId
            }
            if ($retryAfter -gt 0) { $err['retryAfterSeconds'] = $retryAfter }
            if ($reason) { $err['reason'] = $reason }
            if ($scopes) { $err['requiredScopes'] = $scopes }
            $hdrs = @{}
            if ($retryAfter -gt 0) { $hdrs['Retry-After'] = [string]$retryAfter }
            Send-Json $ctx $status @{ error = $err } $hdrs
        }

        while ($listener.IsListening) {
            try {
                $ctx = $listener.GetContext()
            }
            catch {
                break
            }

            try {
                $req = $ctx.Request
                $method = $req.HttpMethod.ToUpperInvariant()
                $path = $req.Url.AbsolutePath
                $query = @{}
                foreach ($qk in $req.QueryString.AllKeys) {
                    if ($null -ne $qk) { $query[$qk] = $req.QueryString.GetValues($qk) }
                }
                $hdrMap = @{}
                foreach ($hk in $req.Headers.AllKeys) {
                    if ($null -ne $hk) { $hdrMap[$hk] = $req.Headers[$hk] }
                }

                $rawBytes = $null
                $rawText = ''
                if ($req.HasEntityBody) {
                    $ms = [System.IO.MemoryStream]::new()
                    $req.InputStream.CopyTo($ms)
                    $rawBytes = $ms.ToArray()
                    $ms.Dispose()
                    if ($req.ContentType -notlike 'application/octet-stream*') {
                        $rawText = [System.Text.Encoding]::UTF8.GetString($rawBytes)
                    }
                }

                [void]$state.Requests.Add([PSCustomObject]@{
                    Method   = $method
                    Path     = $path
                    Query    = $query
                    Headers  = $hdrMap
                    BodyText = $rawText
                    BodyBytes = $rawBytes
                })

                # Auth check unless signed upload URL with ?token=...
                $hasSignedToken = ($path -match '^/v1/machines/[^/]+/files$' -and $method -eq 'PUT' -and $query.ContainsKey('token'))
                $apiKey = $hdrMap['X-API-Key']
                $authHdr = $hdrMap['Authorization']
                if (-not $hasSignedToken) {
                    if ([string]::IsNullOrWhiteSpace($apiKey) -and [string]::IsNullOrWhiteSpace($authHdr)) {
                        Send-Err $ctx 401 'missing_key' 'No credential sent'
                        continue
                    }
                    if ($apiKey -eq 'ibk_expired_test') {
                        Send-Err $ctx 401 'expired_key' 'API key expired'
                        continue
                    }
                }

                # Fault injection hook: transient 503 retryable once
                if ($state.Faults['RetryOnce503'] -gt 0 -and $path -eq '/v1/templates') {
                    $state.Faults['RetryOnce503'] = [int]$state.Faults['RetryOnce503'] - 1
                    Send-Err $ctx 503 'no_capacity' 'No host room right now' $true 1
                    continue
                }

                # --- 1. Auth: GET /v1/me ---
                if ($method -eq 'GET' -and $path -eq '/v1/me') {
                    $isWs = ($apiKey -like 'ibk_workspace*')
                    $me = [ordered]@{
                        userId           = 1001
                        login            = 'riley'
                        name             = 'Riley Carney'
                        admin            = $false
                        inviteRequired   = $false
                        activated        = $true
                        resizeRestart    = $true
                        directSecretRefs = $true
                        alwaysOnAllowed  = $true
                        allowedSpecs     = @(
                            @{ vcpus = 4; memMiB = 8192; persistentDiskGiB = 20 },
                            @{ vcpus = 8; memMiB = 16384; persistentDiskGiB = 20 }
                        )
                        org              = @{ id = ($isWs ? 'org_work456' : 'org_personal123'); name = ($isWs ? 'Acme' : 'riley'); tier = 'pro'; kind = ($isWs ? 'workspace' : 'personal'); alwaysOnAllowed = $true }
                    }
                    if ($isWs) {
                        $me['orgId'] = 'org_work456'
                    }
                    else {
                        $me['email'] = 'riley@example.com'
                        $me['workspaces'] = @(@{ id = 'org_work456'; name = 'Acme'; tier = 'pro'; kind = 'workspace'; alwaysOnAllowed = $true })
                    }
                    if ($state.Faults['MeInviteBlocked']) {
                        $me['inviteRequired'] = $true
                        $me['activated'] = $false
                        $me['waitlist'] = @{ position = 42; referralUrl = 'https://instabox.sh/waitlist?ref=abc' }
                    }
                    Send-Json $ctx 200 $me
                    continue
                }

                # --- 2. Templates: GET /v1/templates ---
                if ($method -eq 'GET' -and $path -eq '/v1/templates') {
                    Send-Json $ctx 200 @{
                        templates = @(
                            @{ id = 'agent-browser'; version = '2026-10-15.4'; digest = 'sha256:111'; arch = 'x86_64'; creatable = $true; latest = $true; default = $true; defaultSpec = @{ vcpus = 4; memMiB = 8192; persistentDiskGiB = 20 }; capabilities = @('identity-reset', 'root-grow', 'activity') },
                            @{ id = 'agent-browser'; version = '2026-10-01.1'; digest = 'sha256:110'; arch = 'x86_64'; creatable = $true; latest = $false; defaultSpec = @{ vcpus = 4; memMiB = 8192; persistentDiskGiB = 20 } },
                            @{ id = 'legacy-box'; version = '2026-08-01.1'; digest = 'sha256:000'; arch = 'x86_64'; hidden = $true; creatable = $false; defaultSpec = @{ vcpus = 4; memMiB = 8192; persistentDiskGiB = 20 } }
                        )
                    }
                    continue
                }

                # --- 3. Machines: GET /v1/machines ---
                if ($method -eq 'GET' -and $path -eq '/v1/machines') {
                    $all = @($state.Machines.Values)
                    if ($query.ContainsKey('metadata')) {
                        foreach ($term in $query['metadata']) {
                            $parts = $term.Split(':', 2)
                            $all = @($all | Where-Object { $_.metadata[$parts[0]] -eq $parts[1] })
                        }
                    }
                    $limit = if ($query.ContainsKey('limit')) { [int]$query['limit'][0] } else { 100 }
                    $offset = if ($query.ContainsKey('cursor')) { [int]$query['cursor'][0] } else { 0 }
                    $slice = @($all | Select-Object -Skip $offset -First $limit)
                    $next = if (($offset + $slice.Count) -lt $all.Count) { [string]($offset + $slice.Count) } else { $null }
                    Send-Json $ctx 200 @{ machines = $slice; nextCursor = $next }
                    continue
                }

                # --- 4. Create machine: POST /v1/machines ---
                if ($method -eq 'POST' -and $path -eq '/v1/machines') {
                    if (-not $hdrMap['Idempotency-Key']) { Send-Err $ctx 400 'bad_request' 'Missing Idempotency-Key'; continue }
                    $body = $rawText | ConvertFrom-Json -AsHashtable
                    foreach ($badKey in @('persistentDiskGiB', 'rootDiskGiB', 'diskGiB', 'timeoutSeconds')) {
                        if ($body.ContainsKey($badKey)) { Send-Err $ctx 400 'unknown_field' "Unknown or disallowed field $badKey"; continue }
                    }
                    $newId = 'm_cccccccccccccccccccccccccc'
                    $boxName = if ($body['name']) { $body['name'] } else { 'box-12345678' }
                    $state.Machines[$newId] = [ordered]@{
                        id = $newId; name = $boxName; desiredState = ($body['desiredState'] ?? 'running'); state = ($body['desiredState'] ?? 'running')
                        revision = 1; operationId = $null
                        template = @{ id = ($body['templateId'] ?? 'agent-browser'); version = '2026-10-15.4'; digest = 'sha256:111' }
                        spec = @{ vcpus = ($body['vcpus'] ?? 4); memMiB = ($body['memMiB'] ?? 8192); persistentDiskGiB = 20 }
                        storage = @{ sizeGiB = 20; mountPath = '/data'; persistent = $true; synced = $true }
                        runtime = @{ ready = (($body['desiredState'] ?? 'running') -eq 'running') }
                        autoSuspendAfterSeconds = 1800; maxRunMinutes = -1; runStartedAt = $null; cooldownUntil = $null
                        metadata = ($body['metadata'] ?? @{}); vault = $true; guestUser = ($body['guestUser'] ?? 'dev')
                        orgId = ($body['orgId'] ?? 'org_personal123'); createdAt = '2026-11-20T01:00:00Z'; updatedAt = '2026-11-20T01:00:00Z'
                    }
                    $opId = 'op_create_' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
                    $state.Operations[$opId] = [ordered]@{
                        id = $opId; machineId = $newId; type = 'create'; state = 'queued'; phase = 'scheduling'; error = $null
                        createdAt = '2026-11-20T01:00:00Z'; updatedAt = '2026-11-20T01:00:00Z'
                    }
                    Send-Json $ctx 202 $state.Operations[$opId]
                    continue
                }

                # --- 5. Operations: GET /v1/operations/{id} ---
                if ($method -eq 'GET' -and $path -match '^/v1/operations/([^/]+)$') {
                    $opId = $Matches[1]
                    if (-not $state.Operations.ContainsKey($opId)) { Send-Err $ctx 404 'not_found' 'Operation not found'; continue }
                    $cnt = [int]($state.OpPollCount[$opId] ?? 0) + 1
                    $state.OpPollCount[$opId] = $cnt
                    $op = $state.Operations[$opId]
                    if ($cnt -eq 1 -and $op['state'] -eq 'queued') {
                        $op['state'] = 'running'; $op['phase'] = 'booting'
                    }
                    elseif ($op['state'] -ne 'failed') {
                        $op['state'] = 'succeeded'; $op['phase'] = 'ready'
                        if ($state.Machines.ContainsKey($op['machineId'])) {
                            $op['machine'] = $state.Machines[$op['machineId']]
                        }
                    }
                    Send-Json $ctx 200 $op
                    continue
                }

                # --- 6. Ports all: GET /v1/ports ---
                if ($method -eq 'GET' -and $path -eq '/v1/ports') {
                    Send-Json $ctx 200 @{ enabled = $true; ports = @($state.Ports.Values) }
                    continue
                }

                # --- 7. Snapshots list / get / delete / files ---
                if ($method -eq 'GET' -and $path -eq '/v1/snapshots') {
                    Send-Json $ctx 200 @{ snapshots = @($state.Snapshots.Values) }
                    continue
                }
                if ($path -match '^/v1/snapshots/([^/]+)$') {
                    $sid = $Matches[1]
                    if (-not $state.Snapshots.ContainsKey($sid)) { Send-Err $ctx 404 'not_found' 'Snapshot not found'; continue }
                    if ($method -eq 'GET') {
                        $sc = [int]($state.SnapPollCount[$sid] ?? 0) + 1
                        $state.SnapPollCount[$sid] = $sc
                        $sn = $state.Snapshots[$sid]
                        if ($sn['status'] -eq 'pending' -and $sc -ge 2) { $sn['status'] = 'ready' }
                        Send-Json $ctx 200 $sn
                        continue
                    }
                    if ($method -eq 'DELETE') {
                        if (-not $hdrMap['Idempotency-Key']) { Send-Err $ctx 400 'bad_request' 'Missing Idempotency-Key'; continue }
                        $cd = $hdrMap['X-Confirm-Delete']
                        $sn = $state.Snapshots[$sid]
                        if ($cd -ne $sid -and $cd -ne $sn['name']) {
                            Send-Err $ctx 409 'delete_confirmation_required' "Send X-Confirm-Delete: $sid"
                            continue
                        }
                        $state.Snapshots.Remove($sid) | Out-Null
                        Send-Json $ctx 204 $null
                        continue
                    }
                }
                if ($method -eq 'GET' -and $path -match '^/v1/snapshots/([^/]+)/files$') {
                    $sid = $Matches[1]
                    $fpath = if ($query.ContainsKey('path')) { $query['path'][0] } else { '/' }
                    if ($fpath -like '/data*') {
                        Send-Err $ctx 400 'data_disk_not_browsable' '/data is on the data disk and is not browsable on snapshots'
                        continue
                    }
                    Send-Json $ctx 200 @{
                        path = $fpath; type = 'dir'; size = 0; mode = 'drwxr-xr-x'; modTime = '2026-11-20T00:00:00Z'
                        entries = @(@{ name = 'etc'; type = 'dir'; size = 0; mode = 'drwxr-xr-x'; modTime = '2026-11-20T00:00:00Z' })
                    }
                    continue
                }

                # --- 8. Usage: GET /v1/usage ---
                if ($method -eq 'GET' -and $path -eq '/v1/usage') {
                    $org = if ($query.ContainsKey('org')) { $query['org'][0] } else { 'org_personal123' }
                    Send-Json $ctx 200 @{
                        computedAt       = '2026-11-20T00:00:00Z'
                        logicalBytes     = 100
                        storedBytes      = 50
                        allocatedDiskGiB = 170
                        exclusiveBytes   = 0
                        machines         = 1
                        snapshots        = 1
                        images           = 1
                        org              = @{ id = $org; name = $org; tier = 'pro'; kind = 'personal' }
                        limits           = @{
                            maxMachines  = 0
                            maxSnapshots = 5
                            maxStoredGiB = 200
                            maxImages    = 5
                            liveSnapshots = $true
                            orgSecrets   = $true
                            unlimited    = @('maxMachines')
                        }
                        cost             = @{
                            periodStart = '2026-11-01T00:00:00Z'; periodEnd = '2026-12-01T00:00:00Z'
                            machines = 1; freeMachines = 0; freeSandboxHours = 0; running = 1; snapshots = 1
                            vcpuHours = 10; memGiBHours = 20; storageGiBHours = 5; egressGiB = 1
                            runtimeUSD = 1.5; vcpuUSD = 1.0; memUSD = 0.5; storageUSD = 0.2; egressUSD = 0.05; costUSD = 1.75
                            allowanceUSD = 10; creditRemainingUSD = 8.25; overageUSD = 0; remainingUSD = 8.25
                            ratedUntil = '2026-11-20T00:00:00Z'; billableDiskGiB = 20; allocatedDiskGiB = 170
                            storedBytes = $null; storageComputedAt = $null; creditsUSD = 25; creditsUsedUSD = 0
                        }
                    }
                    continue
                }

                # --- 9. Org secrets ---
                if ($path -match '^/v1/orgs/([^/]+)/secrets$') {
                    $orgId = [Uri]::UnescapeDataString($Matches[1])
                    if ($method -eq 'GET') {
                        $items = @($state.OrgSecrets.Values | Where-Object { $_.orgId -eq $orgId })
                        Send-Json $ctx 200 @{ items = $items }
                        continue
                    }
                }
                if ($method -eq 'POST' -and $path -match '^/v1/orgs/([^/]+)/secrets/import$') {
                    $orgId = [Uri]::UnescapeDataString($Matches[1])
                    $body = $rawText | ConvertFrom-Json -AsHashtable
                    $created = [System.Collections.Generic.List[object]]::new()
                    foreach ($sk in $body['values'].Keys) {
                        $obj = [ordered]@{
                            id = "sec_$sk"; orgId = $orgId; name = $sk; delivery = $body['delivery']
                            hosts = @($body['hosts'] ?? @()); version = 1; size = ([string]$body['values'][$sk]).Length
                            createdAt = '2026-11-20T01:00:00Z'; updatedAt = '2026-11-20T01:00:00Z'
                        }
                        $state.OrgSecrets["$orgId/$sk"] = $obj
                        $created.Add($obj)
                    }
                    Send-Json $ctx 200 @{ items = $created.ToArray() }
                    continue
                }
                if ($path -match '^/v1/orgs/([^/]+)/secrets/([^/]+)$') {
                    $orgId = [Uri]::UnescapeDataString($Matches[1])
                    $sname = [Uri]::UnescapeDataString($Matches[2])
                    if ($method -eq 'PUT') {
                        $body = $rawText | ConvertFrom-Json -AsHashtable
                        $obj = [ordered]@{
                            id = "sec_$sname"; orgId = $orgId; name = $sname; delivery = $body['delivery']
                            hosts = @($body['hosts'] ?? @()); version = 1; size = ([string]$body['value']).Length
                            createdAt = '2026-11-20T01:00:00Z'; updatedAt = '2026-11-20T01:00:00Z'
                        }
                        $state.OrgSecrets["$orgId/$sname"] = $obj
                        Send-Json $ctx 201 $obj
                        continue
                    }
                    if ($method -eq 'DELETE') {
                        $state.OrgSecrets.Remove("$orgId/$sname") | Out-Null
                        Send-Json $ctx 204 $null
                        continue
                    }
                }

                # --- 10. Per-machine routes ---
                if ($path -match '^/v1/machines/([^/]+)(.*)$') {
                    $mid = $Matches[1]
                    $sub = $Matches[2]
                    if (-not $state.Machines.ContainsKey($mid)) { Send-Err $ctx 404 'not_found' 'Sandbox not found'; continue }
                    $box = $state.Machines[$mid]

                    if ($sub -eq '') {
                        if ($method -eq 'GET') { Send-Json $ctx 200 $box; continue }
                        if ($method -eq 'PATCH') {
                            if (-not $hdrMap['Idempotency-Key']) { Send-Err $ctx 400 'bad_request' 'Missing Idempotency-Key'; continue }
                            $body = $rawText | ConvertFrom-Json -AsHashtable
                            if ($body['name']) { $box['name'] = $body['name'] }
                            if ($body['persistentDiskGiB']) { $box['spec']['persistentDiskGiB'] = [int]$body['persistentDiskGiB'] }
                            if ($body['apply'] -eq 'restart') {
                                if ($body['vcpus']) { $box['spec']['vcpus'] = [int]$body['vcpus'] }
                                if ($body['memMiB']) { $box['spec']['memMiB'] = [int]$body['memMiB'] }
                                $opId = 'op_resize_' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
                                $state.Operations[$opId] = [ordered]@{ id = $opId; machineId = $mid; type = 'resize'; state = 'running'; phase = 'resizing'; error = $null; createdAt = '2026-11-20T01:00:00Z'; updatedAt = '2026-11-20T01:00:00Z' }
                                Send-Json $ctx 202 $state.Operations[$opId]
                                continue
                            }
                            Send-Json $ctx 200 $box
                            continue
                        }
                        if ($method -eq 'DELETE') {
                            if (-not $hdrMap['Idempotency-Key']) { Send-Err $ctx 400 'bad_request' 'Missing Idempotency-Key'; continue }
                            $cd = $hdrMap['X-Confirm-Delete']
                            if ($cd -ne $mid -and $cd -ne $box['name']) {
                                Send-Err $ctx 409 'delete_confirmation_required' "X-Confirm-Delete must match $mid or $($box['name'])"
                                continue
                            }
                            $state.Machines.Remove($mid) | Out-Null
                            $opId = 'op_del_' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
                            $state.Operations[$opId] = [ordered]@{ id = $opId; machineId = $mid; type = 'delete'; state = 'succeeded'; phase = 'deleted'; error = $null; createdAt = '2026-11-20T01:00:00Z'; updatedAt = '2026-11-20T01:00:00Z' }
                            Send-Json $ctx 202 $state.Operations[$opId]
                            continue
                        }
                    }

                    if ($method -eq 'POST' -and $sub -in @('/start', '/stop', '/suspend', '/resume', '/restore')) {
                        if (-not $hdrMap['Idempotency-Key']) { Send-Err $ctx 400 'bad_request' 'Missing Idempotency-Key'; continue }
                        $opType = $sub.TrimStart('/')
                        if ($opType -eq 'start' -or $opType -eq 'resume') { $box['state'] = 'running'; $box['runtime']['ready'] = $true }
                        elseif ($opType -eq 'stop') { $box['state'] = 'stopped'; $box['runtime']['ready'] = $false }
                        elseif ($opType -eq 'suspend') { $box['state'] = 'suspended'; $box['runtime']['ready'] = $false }
                        $opId = "op_${opType}_" + ([guid]::NewGuid().ToString('N').Substring(0, 6))
                        $state.Operations[$opId] = [ordered]@{ id = $opId; machineId = $mid; type = $opType; state = 'running'; phase = 'applying'; error = $null; createdAt = '2026-11-20T01:00:00Z'; updatedAt = '2026-11-20T01:00:00Z' }
                        Send-Json $ctx 202 $state.Operations[$opId]
                        continue
                    }

                    if ($method -eq 'POST' -and $sub -eq '/wake') {
                        $box['state'] = 'running'; $box['runtime']['ready'] = $true
                        Send-Json $ctx 200 $box
                        continue
                    }

                    if ($method -eq 'POST' -and $sub -eq '/fork') {
                        if (-not $hdrMap['Idempotency-Key']) { Send-Err $ctx 400 'bad_request' 'Missing Idempotency-Key'; continue }
                        if ($state.Faults['ForkUnavailable']) {
                            $state.Faults['ForkUnavailable'] = $false
                            Send-Err $ctx 409 'fork_unavailable' 'Host cannot fork right now' $false 0 $null 'source_host_full'
                            continue
                        }
                        $forkId = 'm_dddddddddddddddddddddddddd'
                        $state.Machines[$forkId] = [ordered]@{
                            id = $forkId; name = "$($box['name'])-fork"; desiredState = 'running'; state = 'running'
                            revision = 1; operationId = $null; template = $box['template']; spec = $box['spec']
                            storage = $box['storage']; runtime = @{ ready = $true }; autoSuspendAfterSeconds = 1800
                            maxRunMinutes = -1; runStartedAt = $null; cooldownUntil = $null
                            metadata = @{ 'instabox-fork-of' = $mid }; vault = $true; guestUser = 'dev'
                            orgId = $box['orgId']; createdAt = '2026-11-20T01:00:00Z'; updatedAt = '2026-11-20T01:00:00Z'
                        }
                        $opId = 'op_fork_' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
                        $state.Operations[$opId] = [ordered]@{ id = $opId; machineId = $forkId; type = 'create'; state = 'succeeded'; phase = 'ready'; forkInherited = $true; error = $null; createdAt = '2026-11-20T01:00:00Z'; updatedAt = '2026-11-20T01:00:00Z'; machine = $state.Machines[$forkId] }
                        Send-Json $ctx 202 $state.Operations[$opId]
                        continue
                    }

                    # Files
                    if ($sub -eq '/files') {
                        $fpath = if ($query.ContainsKey('path')) { $query['path'][0] } else { '/' }
                        if ($method -eq 'GET') {
                            $key = "$mid`:$fpath"
                            if ($state.Files.ContainsKey($key)) {
                                $txt = [System.Text.Encoding]::UTF8.GetString($state.Files[$key])
                                Send-Json $ctx 200 @{ path = $fpath; type = 'file'; size = $state.Files[$key].Length; mode = '-rw-r--r--'; modTime = '2026-11-20T00:00:00Z'; content = $txt; binary = $false }
                            }
                            else {
                                Send-Json $ctx 200 @{ path = $fpath; type = 'dir'; size = 0; mode = 'drwxr-xr-x'; modTime = '2026-11-20T00:00:00Z'; entries = @(@{ name = 'hello.txt'; type = 'file'; size = 20; mode = '-rw-r--r--'; modTime = '2026-11-20T00:00:00Z' }) }
                            }
                            continue
                        }
                        if ($method -eq 'PUT') {
                            if ($state.Faults['UploadBare413']) {
                                $state.Faults['UploadBare413'] = $false
                                # Intentionally bare Error object matching OpenAPI spec quirk
                                Send-Json $ctx 413 @{ code = 'too_large'; message = 'File over 5 GiB'; requestId = 'req_413'; retryable = $false; operationId = $null }
                                continue
                            }
                            $bytes = if ($null -ne $rawBytes) { $rawBytes } else { [byte[]]@() }
                            $state.Files["$mid`:$fpath"] = $bytes
                            $sha = ([BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($bytes)) -replace '-', '').ToLowerInvariant()
                            Send-Json $ctx 201 @{ path = $fpath; size = $bytes.Length; sha256 = $sha; mode = ($query['mode'] ? $query['mode'][0] : '0644'); created = $true }
                            continue
                        }
                    }

                    if ($method -eq 'GET' -and $sub -eq '/files/content') {
                        $fpath = $query['path'][0]
                        $key = "$mid`:$fpath"
                        if (-not $state.Files.ContainsKey($key)) { Send-Err $ctx 404 'not_found' 'File not found'; continue }
                        $allBytes = [byte[]]$state.Files[$key]
                        $etag = $state.FileEtags[$key] ?? '"etag-default"'
                        $rangeHdr = $hdrMap['Range']
                        $ifRange = $hdrMap['If-Range']

                        $resp = $ctx.Response
                        $resp.Headers.Add('X-Instabox-File-Path', [Uri]::EscapeDataString($fpath))
                        $resp.Headers.Add('X-Instabox-File-Mode', '0644')
                        $resp.Headers.Add('Accept-Ranges', 'bytes')
                        $resp.Headers.Add('ETag', $etag)
                        $resp.ContentType = 'application/octet-stream'

                        if ($rangeHdr -and $rangeHdr -match '^bytes=(\d+)-$' -and (-not $ifRange -or $ifRange -eq $etag)) {
                            $start = [int]$Matches[1]
                            if ($start -ge $allBytes.Length) {
                                Send-Err $ctx 416 'bad_request' 'Range past end'
                                continue
                            }
                            $len = $allBytes.Length - $start
                            $resp.StatusCode = 206
                            $resp.Headers.Add('Content-Range', "bytes $start-$($allBytes.Length - 1)/$($allBytes.Length)")
                            $resp.ContentLength64 = $len
                            $resp.OutputStream.Write($allBytes, $start, $len)
                            $resp.Close()
                            continue
                        }

                        if ($state.Faults['TruncateFirstDownload']) {
                            $state.Faults['TruncateFirstDownload'] = $false
                            $resp.StatusCode = 200
                            $resp.ContentLength64 = $allBytes.Length
                            $half = [Math]::Floor($allBytes.Length / 2)
                            $resp.OutputStream.Write($allBytes, 0, $half)
                            $resp.OutputStream.Flush()
                            $resp.Abort()
                            continue
                        }

                        $resp.StatusCode = 200
                        $resp.ContentLength64 = $allBytes.Length
                        $resp.OutputStream.Write($allBytes, 0, $allBytes.Length)
                        $resp.Close()
                        continue
                    }

                    if ($method -eq 'POST' -and $sub -eq '/files/upload-url') {
                        $body = $rawText | ConvertFrom-Json -AsHashtable
                        $pEncoded = [Uri]::EscapeDataString([string]$body['path'])
                        Send-Json $ctx 201 @{
                            url       = "$($state.BaseUrl)/v1/machines/$mid/files?path=$pEncoded&token=signed_tok_123"
                            method    = 'PUT'
                            path      = $body['path']
                            expiresAt = '2026-11-20T02:00:00Z'
                            maxBytes  = 5368709120
                        }
                        continue
                    }

                    # Connections (SSH cert) & SSH Tokens
                    if ($method -eq 'POST' -and $sub -eq '/connections') {
                        if (-not $hdrMap['Idempotency-Key']) { Send-Err $ctx 400 'bad_request' 'Missing Idempotency-Key'; continue }
                        Send-Json $ctx 201 @{
                            id          = 'cn_cert123'
                            machineId   = $mid
                            transport   = 'ssh'
                            host        = 'ssh.instabox.sh'
                            port        = 2222
                            username    = $mid
                            certificate = 'ssh-ed25519-cert-v01@openssh.com AAAAMOCKCERT'
                            expiresAt   = '2026-11-20T03:00:00Z'
                            hostTrust   = @{ type = 'ca'; publicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMOCKCA'; principals = @($mid) }
                        }
                        continue
                    }

                    if ($sub -eq '/ssh-tokens') {
                        if ($method -eq 'POST') {
                            $tid = 'cn_tok_' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
                            $tokStr = 'ibssh_' + ('a' * 26)
                            $state.SshTokens[$tid] = [ordered]@{ id = $tid; name = 'instabox-ps'; createdAt = '2026-11-20T01:00:00Z'; expiresAt = '2026-11-27T01:00:00Z' }
                            Send-Json $ctx 201 @{
                                id = $tid; name = 'instabox-ps'; machineId = $mid; host = 'ssh.instabox.sh'; port = 2222
                                token = $tokStr; command = "ssh -p 2222 $tokStr@ssh.instabox.sh"
                                moshCommand = "mosh --ssh=`"ssh -p 2222`" $tokStr@ssh.instabox.sh"
                                expiresAt = '2026-11-27T01:00:00Z'; hostKeyFingerprint = 'SHA256:MockHostKeyFp'
                            }
                            continue
                        }
                        if ($method -eq 'GET') {
                            Send-Json $ctx 200 @{ tokens = @($state.SshTokens.Values) }
                            continue
                        }
                        if ($method -eq 'DELETE') {
                            $cnt = $state.SshTokens.Count
                            $state.SshTokens.Clear()
                            Send-Json $ctx 200 @{ revoked = $cnt }
                            continue
                        }
                    }
                    if ($method -eq 'DELETE' -and $sub -match '^/ssh-tokens/([^/]+)$') {
                        $state.SshTokens.Remove($Matches[1]) | Out-Null
                        Send-Json $ctx 204 $null
                        continue
                    }

                    # Exec
                    if ($method -eq 'POST' -and $sub -eq '/exec') {
                        $body = $rawText | ConvertFrom-Json -AsHashtable
                        $accept = $hdrMap['Accept']
                        if ($accept -like '*text/event-stream*') {
                            $resp = $ctx.Response
                            $resp.StatusCode = 200
                            $resp.ContentType = 'text/event-stream'
                            $sse = ": ping`n`nevent: stdout`ndata: {`"data`":`"stream-line1\n`"}`n`nevent: stderr`ndata: {`"data`":`"warn1\n`"}`n`nevent: exit`ndata: {`"stdout`":`"`",`"stderr`":`"`",`"exitCode`":0,`"timedOut`":false,`"truncated`":false,`"oomKilled`":false}`n`n"
                            $b = [System.Text.Encoding]::UTF8.GetBytes($sse)
                            $resp.ContentLength64 = $b.Length
                            $resp.OutputStream.Write($b, 0, $b.Length)
                            $resp.Close()
                            continue
                        }
                        if ($state.Faults['ExecKeepalivePost200Error']) {
                            $state.Faults['ExecKeepalivePost200Error'] = $false
                            $errPayload = "`n`n" + (@{ error = @{ code = 'host_unavailable'; message = 'Lost host mid-command'; requestId = 'req_k1'; retryable = $false; operationId = $null }; status = 503 } | ConvertTo-Json -Depth 10 -Compress)
                            $b = [System.Text.Encoding]::UTF8.GetBytes($errPayload)
                            $ctx.Response.StatusCode = 200
                            $ctx.Response.ContentType = 'application/json'
                            $ctx.Response.ContentLength64 = $b.Length
                            $ctx.Response.OutputStream.Write($b, 0, $b.Length)
                            $ctx.Response.Close()
                            continue
                        }
                        if ($state.Faults['Exec503NonRetryable']) {
                            $state.Faults['Exec503NonRetryable'] = $false
                            Send-Err $ctx 503 'host_unavailable' 'Lost host after start' $false
                            continue
                        }
                        $outText = if ($body['argv']) { ($body['argv'] -join '|') } else { "ran:$($body['cmd'])" }
                        $payload = "`n`n" + (@{ stdout = $outText; stderr = ''; exitCode = 0; timedOut = $false; truncated = $false } | ConvertTo-Json -Compress)
                        $b = [System.Text.Encoding]::UTF8.GetBytes($payload)
                        $ctx.Response.StatusCode = 200
                        $ctx.Response.ContentType = 'application/json'
                        $ctx.Response.ContentLength64 = $b.Length
                        $ctx.Response.OutputStream.Write($b, 0, $b.Length)
                        $ctx.Response.Close()
                        continue
                    }

                    # Ports per machine
                    if ($sub -eq '/ports') {
                        if ($method -eq 'GET') {
                            $list = @($state.Ports.Values | Where-Object { $_.machineId -eq $mid })
                            Send-Json $ctx 200 @{ enabled = $true; ports = $list }
                            continue
                        }
                        if ($method -eq 'POST') {
                            $body = $rawText | ConvertFrom-Json -AsHashtable
                            $pnum = [int]$body['port']
                            $proto = $body['protocol'] ?? 'http'
                            $acc = $body['access'] ?? 'public'
                            $pid = "prt_${pnum}_" + ([guid]::NewGuid().ToString('N').Substring(0, 6))
                            $pub = [ordered]@{
                                id = $pid; machineId = $mid; port = $pnum; name = ($body['name'] ?? "Port $pnum")
                                protocol = $proto; access = $acc; createdAt = '2026-11-20T01:00:00Z'
                                url = if ($proto -eq 'tcp') { "tls://$pnum-$mid.tcp.instabox.sh:443" } else { "https://$pnum-$mid.instabox.sh" }
                            }
                            if ($proto -eq 'tcp') { $pub['address'] = "$pnum-$mid.tcp.instabox.sh:443" }
                            if ($acc -eq 'private') {
                                $tok = 'ibp_mocksecret_' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
                                $pub['token'] = $tok
                                $pub['tokenUrl'] = "$($pub['url'])?_token=$tok"
                            }
                            $state.Ports["$mid`:$pnum"] = $pub
                            Send-Json $ctx 201 $pub
                            continue
                        }
                    }
                    if ($method -eq 'DELETE' -and $sub -match '^/ports/(\d+)$') {
                        $state.Ports.Remove("$mid`:$($Matches[1])") | Out-Null
                        Send-Json $ctx 204 $null
                        continue
                    }

                    # Machine Secrets
                    if ($sub -eq '/secrets') {
                        if (-not $state.MachineSecrets.ContainsKey($mid)) {
                            $state.MachineSecrets[$mid] = [ordered]@{
                                secrets = 'all'; envSecrets = @(); directSecrets = @(); items = @(); version = 1
                                proxy = @{ state = 'applied'; revision = 1; appliedRevision = 1 }
                                guest = @{ state = 'applied'; revision = 1; appliedRevision = 1; items = @() }
                            }
                        }
                        $ms = $state.MachineSecrets[$mid]
                        if ($method -eq 'GET') { Send-Json $ctx 200 $ms; continue }
                        if ($method -eq 'PATCH') {
                            $body = $rawText | ConvertFrom-Json -AsHashtable
                            if ($body.ContainsKey('secrets')) { $ms['secrets'] = $body['secrets'] }
                            if ($body.ContainsKey('envSecrets')) { $ms['envSecrets'] = @($body['envSecrets']) }
                            if ($body.ContainsKey('directSecrets')) { $ms['directSecrets'] = @($body['directSecrets']) }
                            $ms['version'] = [int]$ms['version'] + 1
                            Send-Json $ctx 200 $ms
                            continue
                        }
                        if ($method -eq 'POST') {
                            Send-Json $ctx 200 $ms
                            continue
                        }
                    }

                    # Save snapshot: POST /v1/machines/{id}/snapshots
                    if ($method -eq 'POST' -and $sub -eq '/snapshots') {
                        if (-not $hdrMap['Idempotency-Key']) { Send-Err $ctx 400 'bad_request' 'Missing Idempotency-Key'; continue }
                        $body = $rawText | ConvertFrom-Json -AsHashtable
                        $sid = 'sn_new_' + ([guid]::NewGuid().ToString('N').Substring(0, 19))
                        #pad to 26 chars after sn_
                        $sid = ('sn_' + ('b' * 26))
                        $isRunning = ($box['state'] -eq 'running')
                        $snap = [ordered]@{
                            id = $sid; name = $body['name']; orgId = $box['orgId']; sourceMachineId = $mid; sourceSnapshotSeq = 1
                            status = ($isRunning ? 'pending' : 'ready')
                            template = $box['template']; rootSizeBytes = 10737418240; sizeLocked = $true
                            defaultSpec = $box['spec']; createdAt = '2026-11-20T01:00:00Z'
                        }
                        if (-not $body['rootOnly']) { $snap['dataSizeBytes'] = 21474836480 }
                        $state.Snapshots[$sid] = $snap
                        Send-Json $ctx ($isRunning ? 202 : 201) $snap
                        continue
                    }
                }

                Send-Err $ctx 404 'not_found' "Unhandled route $method $path"
            }
            catch {
                try {
                    Send-Err $ctx 500 'internal' "Mock exception: $($_.Exception.Message)"
                }
                catch { }
            }
        }
    })
    $null = $ps.AddArgument($listener).AddArgument($state)
    $handle = $ps.BeginInvoke()

    return [PSCustomObject]@{
        BaseUrl  = $baseUrl
        State    = $state
        Listener = $listener
        Worker   = $ps
        Handle   = $handle
    }
}

function Stop-MockInstaboxServer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Server
    )

    try { $Server.Listener.Stop() } catch { }
    try { $Server.Listener.Close() } catch { }
    try { $Server.Worker.EndInvoke($Server.Handle) } catch { }
    try { $Server.Worker.Dispose() } catch { }
}
