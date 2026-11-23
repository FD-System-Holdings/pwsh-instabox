function Get-InstaboxHttpClient {
    [CmdletBinding()]
    param()

    if ($null -eq $script:InstaboxSession.HttpClient) {
        $handler = [System.Net.Http.SocketsHttpHandler]::new()
        $handler.PooledConnectionLifetime = [TimeSpan]::FromMinutes(15)
        $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
        $client.DefaultRequestHeaders.UserAgent.ParseAdd('instabox-pwsh/0.1.0')
        $script:InstaboxSession.HttpClient = $client
    }
    return $script:InstaboxSession.HttpClient
}

function ConvertFrom-InstaboxErrorJson {
    [CmdletBinding()]
    param(
        [int]$StatusCode,
        [AllowEmptyString()]
        [string]$RawBody,
        [Nullable[int]]$HeaderRetryAfter = $null
    )

    $errObj = $null
    $effectiveStatus = $StatusCode

    if (-not [string]::IsNullOrWhiteSpace($RawBody)) {
        try {
            $parsed = $RawBody | ConvertFrom-Json -Depth 10
            if ($null -ne $parsed) {
                if ($null -ne $parsed.PSObject.Properties['status'] -and $null -ne $parsed.status) {
                    $effectiveStatus = [int]$parsed.status
                }
                if ($null -ne $parsed.PSObject.Properties['error'] -and $null -ne $parsed.error) {
                    $errObj = $parsed.error
                }
                elseif ($null -ne $parsed.PSObject.Properties['code']) {
                    # Bare Error object (matches 413/507 spec discrepancy on PUT .../files)
                    $errObj = $parsed
                }
            }
        }
        catch {
            # Non-JSON error body
        }
    }

    $code = if ($errObj -and $errObj.code) { [string]$errObj.code } else { "http_$effectiveStatus" }
    $msg = if ($errObj -and $errObj.message) { [string]$errObj.message } elseif (-not [string]::IsNullOrWhiteSpace($RawBody)) { $RawBody.Trim() } else { "HTTP $effectiveStatus error" }
    $ex = [Instabox.InstaboxApiException]::new($msg)
    $ex.StatusCode = $effectiveStatus
    $ex.Code = $code
    $ex.RawBody = if ($null -eq $RawBody) { '' } else { $RawBody }

    if ($errObj) {
        if ($errObj.requestId) { $ex.RequestId = [string]$errObj.requestId }
        if ($null -ne $errObj.retryable) { $ex.Retryable = [bool]$errObj.retryable }
        if ($errObj.operationId) { $ex.OperationId = [string]$errObj.operationId }
        if ($errObj.reason) { $ex.Reason = [string]$errObj.reason }
        if ($errObj.hint) { $ex.Hint = [string]$errObj.hint }
        if ($errObj.docs) { $ex.Docs = [string]$errObj.docs }
        if ($errObj.docs_url) { $ex.DocsUrl = [string]$errObj.docs_url }
        if ($errObj.at) { $ex.At = [string]$errObj.at }
        if ($null -ne $errObj.requiredScopes) {
            $ex.RequiredScopes = [string[]]@($errObj.requiredScopes | ForEach-Object { [string]$_ })
        }
        if ($null -ne $errObj.retryAfterSeconds) {
            $ex.RetryAfterSeconds = [Nullable[int]][int]$errObj.retryAfterSeconds
        }
    }

    if ($null -eq $ex.RetryAfterSeconds -and $null -ne $HeaderRetryAfter) {
        $ex.RetryAfterSeconds = $HeaderRetryAfter
    }

    return $ex
}

function Get-InstaboxRetryAfterHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Http.HttpResponseMessage]$Response
    )

    if ($null -ne $Response.Headers.RetryAfter) {
        if ($null -ne $Response.Headers.RetryAfter.Delta) {
            return [Nullable[int]][Math]::Max(1, [int][Math]::Ceiling($Response.Headers.RetryAfter.Delta.TotalSeconds))
        }
        if ($null -ne $Response.Headers.RetryAfter.Date) {
            $secs = [int][Math]::Ceiling(($Response.Headers.RetryAfter.Date - [DateTimeOffset]::UtcNow).TotalSeconds)
            if ($secs -gt 0) {
                return [Nullable[int]]$secs
            }
        }
    }
    $vals = $null
    if ($Response.Headers.TryGetValues('Retry-After', [ref]$vals)) {
        $first = ($vals | Select-Object -First 1)
        $parsed = 0
        if ([int]::TryParse($first, [ref]$parsed) -and $parsed -gt 0) {
            return [Nullable[int]]$parsed
        }
    }
    return $null
}

function Test-InstaboxResponseNotices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Http.HttpResponseMessage]$Response,
        [string]$Method,
        [string]$Path
    )

    $vals = $null
    if ($Response.Headers.TryGetValues('Warning', [ref]$vals)) {
        foreach ($v in $vals) {
            Write-InstaboxLog -Level 'WARN' -Message "Server Warning on $Method $Path`: $v"
            Write-Warning "Instabox server warning: $v"
        }
    }
    if ($Response.Headers.TryGetValues('Deprecation', [ref]$vals)) {
        $dep = ($vals | Select-Object -First 1)
        Write-InstaboxLog -Level 'WARN' -Message "Deprecated endpoint $Method $Path (Deprecation: $dep)"
    }
}

function Add-InstaboxAuthHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Http.HttpRequestMessage]$Request,

        [ValidateSet('Default', 'None')]
        [string]$AuthMode = 'Default',

        [string]$ExplicitToken
    )

    if ($AuthMode -eq 'None') {
        return
    }

    $cred = if (-not [string]::IsNullOrWhiteSpace($ExplicitToken)) {
        $ExplicitToken
    }
    else {
        Get-InstaboxSecretValue -Name 'apiKey'
    }

    if ([string]::IsNullOrWhiteSpace($cred)) {
        $ex = [Instabox.InstaboxApiException]::new("Not signed in. Run Connect-Instabox or 'instabox.ps1 login' with an API key first.")
        $ex.StatusCode = 401
        $ex.Code = 'missing_key'
        $ex.Hint = "Create an API key at https://dashboard.instabox.sh/dashboard/api-keys and pass it to Connect-Instabox."
        throw $ex
    }

    if ($cred.StartsWith('iba_', [StringComparison]::Ordinal)) {
        $Request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $cred)
    }
    else {
        $Request.Headers.TryAddWithoutValidation('X-API-Key', $cred) | Out-Null
    }
}

function Invoke-InstaboxRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Path,

        [hashtable]$Query,

        $Body,

        [switch]$RequireIdempotency,

        [string]$IdempotencyKey,

        [string]$ConfirmDelete,

        [hashtable]$ExtraHeaders,

        [ValidateSet('Default', 'None')]
        [string]$AuthMode = 'Default',

        [string]$ExplicitToken,

        [int]$TimeoutSeconds = 60,

        [bool]$AllowRetry = $true,

        [int]$MaxRetries = 3,

        [string]$AbsoluteUrl
    )

    $cfg = Get-InstaboxConfigInternal
    $baseUrl = ([string]$cfg.ApiBaseUrl).TrimEnd('/')

    if ([string]::IsNullOrWhiteSpace($AbsoluteUrl)) {
        $uriStr = "$baseUrl$Path"
        if ($Query -and $Query.Count -gt 0) {
            $pairs = [System.Collections.Generic.List[string]]::new()
            foreach ($k in $Query.Keys) {
                $val = $Query[$k]
                if ($null -eq $val) { continue }
                if ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
                    foreach ($item in $val) {
                        if ($null -ne $item) {
                            $pairs.Add("$([Uri]::EscapeDataString([string]$k))=$([Uri]::EscapeDataString([string]$item))")
                        }
                    }
                }
                elseif ($val -is [bool]) {
                    $pairs.Add("$([Uri]::EscapeDataString([string]$k))=$($val.ToString().ToLowerInvariant())")
                }
                else {
                    $pairs.Add("$([Uri]::EscapeDataString([string]$k))=$([Uri]::EscapeDataString([string]$val))")
                }
            }
            if ($pairs.Count -gt 0) {
                $sep = if ($uriStr.Contains('?')) { '&' } else { '?' }
                $uriStr = "$uriStr$sep$($pairs -join '&')"
            }
        }
    }
    else {
        $uriStr = $AbsoluteUrl
    }

    $effectiveIdempotencyKey = $null
    if ($RequireIdempotency -or -not [string]::IsNullOrWhiteSpace($IdempotencyKey)) {
        $effectiveIdempotencyKey = if (-not [string]::IsNullOrWhiteSpace($IdempotencyKey)) {
            Assert-InstaboxIdempotencyKey -Key $IdempotencyKey
        }
        else {
            [guid]::NewGuid().ToString()
        }
    }

    $jsonBody = $null
    if ($null -ne $Body) {
        if ($Body -is [string]) {
            $jsonBody = $Body
        }
        else {
            $jsonBody = $Body | ConvertTo-Json -Depth 10 -Compress
        }
    }

    $client = Get-InstaboxHttpClient
    $attempt = 0

    while ($true) {
        $attempt++
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), $uriStr)
        $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))

        try {
            Add-InstaboxAuthHeader -Request $req -AuthMode $AuthMode -ExplicitToken $ExplicitToken
            $req.Headers.Accept.ParseAdd('application/json')

            if ($effectiveIdempotencyKey) {
                $req.Headers.TryAddWithoutValidation('Idempotency-Key', $effectiveIdempotencyKey) | Out-Null
            }
            if (-not [string]::IsNullOrWhiteSpace($ConfirmDelete)) {
                $req.Headers.TryAddWithoutValidation('X-Confirm-Delete', $ConfirmDelete) | Out-Null
            }
            if ($ExtraHeaders) {
                foreach ($hk in $ExtraHeaders.Keys) {
                    $req.Headers.TryAddWithoutValidation([string]$hk, [string]$ExtraHeaders[$hk]) | Out-Null
                }
            }
            if ($null -ne $jsonBody) {
                $req.Content = [System.Net.Http.StringContent]::new($jsonBody, [System.Text.Encoding]::UTF8, 'application/json')
            }

            Write-InstaboxLog -Level 'DEBUG' -Message "HTTP $Method $uriStr (attempt=$attempt)"
            $resp = $client.SendAsync($req, $cts.Token).GetAwaiter().GetResult()
            try {
                Test-InstaboxResponseNotices -Response $resp -Method $Method -Path $uriStr
                $statusCode = [int]$resp.StatusCode
                $respBody = $resp.Content.ReadAsStringAsync($cts.Token).GetAwaiter().GetResult()

                if ($resp.IsSuccessStatusCode) {
                    if ($statusCode -eq 204 -or [string]::IsNullOrWhiteSpace($respBody)) {
                        return [PSCustomObject]@{
                            StatusCode = $statusCode
                            Data       = $null
                        }
                    }
                    $parsed = $respBody | ConvertFrom-Json -Depth 20
                    return [PSCustomObject]@{
                        StatusCode = $statusCode
                        Data       = $parsed
                    }
                }

                $headerRetryAfter = Get-InstaboxRetryAfterHeader -Response $resp
                $ex = ConvertFrom-InstaboxErrorJson -StatusCode $statusCode -RawBody $respBody -HeaderRetryAfter $headerRetryAfter
                Write-InstaboxLog -Level 'WARN' -Message "HTTP $statusCode on $Method $uriStr code=$($ex.Code) requestId=$($ex.RequestId) retryable=$($ex.Retryable)"

                if ($AllowRetry -and $ex.Retryable -and $attempt -le $MaxRetries) {
                    $waitSec = if ($null -ne $ex.RetryAfterSeconds) { [double]$ex.RetryAfterSeconds } else { [Math]::Pow(2, $attempt - 1) }
                    $delayMs = [int][Math]::Round($waitSec * 1000.0 * [double]$script:InstaboxSession.RetryDelayScale)
                    if ($delayMs -gt 0) {
                        Start-Sleep -Milliseconds $delayMs
                    }
                    continue
                }

                throw $ex
            }
            finally {
                $resp.Dispose()
            }
        }
        catch [Instabox.InstaboxApiException] {
            throw
        }
        catch [System.OperationCanceledException] {
            throw [System.TimeoutException]::new("Request $Method $uriStr timed out after $TimeoutSeconds seconds.", $_.Exception)
        }
        finally {
            $cts.Dispose()
            $req.Dispose()
        }
    }
}

function Invoke-InstaboxExecRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$MachineId,

        [Parameter(Mandatory)]
        [hashtable]$Body,

        [switch]$Stream,

        [bool]$Keepalive = $true,

        [int]$TimeoutSeconds = 60,

        [scriptblock]$OnOutput
    )

    $cfg = Get-InstaboxConfigInternal
    $baseUrl = ([string]$cfg.ApiBaseUrl).TrimEnd('/')
    $uriStr = "$baseUrl/v1/machines/$([Uri]::EscapeDataString($MachineId))/exec"
    $jsonBody = $Body | ConvertTo-Json -Depth 10 -Compress

    $client = Get-InstaboxHttpClient
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $uriStr)
    $httpTimeout = [Math]::Max(30, $TimeoutSeconds + 30)
    $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($httpTimeout))

    try {
        Add-InstaboxAuthHeader -Request $req
        if ($Stream) {
            $req.Headers.Accept.ParseAdd('text/event-stream')
        }
        else {
            $req.Headers.Accept.ParseAdd('application/json')
            if ($Keepalive) {
                $req.Headers.TryAddWithoutValidation('X-Instabox-Exec-Keepalive', '1') | Out-Null
            }
        }
        $req.Content = [System.Net.Http.StringContent]::new($jsonBody, [System.Text.Encoding]::UTF8, 'application/json')

        Write-InstaboxLog -Level 'DEBUG' -Message "HTTP POST $uriStr (stream=$($Stream.IsPresent), keepalive=$Keepalive)"
        $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token).GetAwaiter().GetResult()
        try {
            $statusCode = [int]$resp.StatusCode
            $mediaType = if ($resp.Content.Headers.ContentType) { $resp.Content.Headers.ContentType.MediaType } else { '' }

            if (-not $resp.IsSuccessStatusCode -or ($Stream -and $mediaType -eq 'application/json')) {
                $rawErr = $resp.Content.ReadAsStringAsync($cts.Token).GetAwaiter().GetResult()
                $retryHdr = Get-InstaboxRetryAfterHeader -Response $resp
                $ex = ConvertFrom-InstaboxErrorJson -StatusCode $statusCode -RawBody $rawErr -HeaderRetryAfter $retryHdr
                Write-InstaboxLog -Level 'WARN' -Message "Exec error $statusCode on $uriStr code=$($ex.Code) requestId=$($ex.RequestId)"
                throw $ex
            }

            if (-not $Stream) {
                $rawBody = $resp.Content.ReadAsStringAsync($cts.Token).GetAwaiter().GetResult()
                $trimmed = $rawBody.Trim()
                $parsed = $trimmed | ConvertFrom-Json -Depth 20
                if ($null -ne $parsed -and $null -ne $parsed.PSObject.Properties['error'] -and $null -ne $parsed.error) {
                    $ex = ConvertFrom-InstaboxErrorJson -StatusCode $statusCode -RawBody $trimmed
                    throw $ex
                }
                return $parsed
            }

            # Stream SSE frames: stdout / stderr / : ping / exit / error
            $streamObj = $resp.Content.ReadAsStreamAsync($cts.Token).GetAwaiter().GetResult()
            $reader = [System.IO.StreamReader]::new($streamObj, [System.Text.Encoding]::UTF8)
            try {
                $stdoutBuf = [System.Text.StringBuilder]::new()
                $stderrBuf = [System.Text.StringBuilder]::new()
                $currentEvent = ''
                $dataLines = [System.Collections.Generic.List[string]]::new()
                $exitResult = $null

                $dispatchEvent = {
                    if ($dataLines.Count -eq 0 -and [string]::IsNullOrEmpty($currentEvent)) {
                        return
                    }
                    $payloadText = $dataLines -join "`n"
                    $evt = if ([string]::IsNullOrEmpty($currentEvent)) { 'message' } else { $currentEvent }
                    $dataLines.Clear()
                    $currentEvent = ''

                    switch ($evt) {
                        'stdout' {
                            $chunkObj = $payloadText | ConvertFrom-Json
                            $txt = [string]$chunkObj.data
                            [void]$stdoutBuf.Append($txt)
                            if ($OnOutput) {
                                & $OnOutput 'stdout' $txt
                            }
                            else {
                                [Console]::Out.Write($txt)
                            }
                        }
                        'stderr' {
                            $chunkObj = $payloadText | ConvertFrom-Json
                            $txt = [string]$chunkObj.data
                            [void]$stderrBuf.Append($txt)
                            if ($OnOutput) {
                                & $OnOutput 'stderr' $txt
                            }
                            else {
                                [Console]::Error.Write($txt)
                            }
                        }
                        'exit' {
                            $exitObj = $payloadText | ConvertFrom-Json -Depth 10
                            $exitResult = $exitObj
                        }
                        'error' {
                            $errEx = ConvertFrom-InstaboxErrorJson -StatusCode 503 -RawBody $payloadText
                            throw $errEx
                        }
                    }
                }

                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLineAsync($cts.Token).GetAwaiter().GetResult()
                    if ($null -eq $line) { break }

                    if ($line.StartsWith(':')) {
                        # SSE comment (: ping)
                        continue
                    }
                    if ($line -eq '') {
                        . $dispatchEvent
                        continue
                    }
                    if ($line.StartsWith('event:')) {
                        $currentEvent = $line.Substring(6).Trim()
                    }
                    elseif ($line.StartsWith('data:')) {
                        $d = $line.Substring(5)
                        if ($d.StartsWith(' ')) { $d = $d.Substring(1) }
                        $dataLines.Add($d)
                    }
                }
                . $dispatchEvent

                if ($null -eq $exitResult) {
                    throw [System.IO.EndOfStreamException]::new("SSE exec stream ended before receiving 'exit' event.")
                }

                if ([string]::IsNullOrEmpty($exitResult.stdout) -and $stdoutBuf.Length -gt 0) {
                    $exitResult.stdout = $stdoutBuf.ToString()
                }
                if ([string]::IsNullOrEmpty($exitResult.stderr) -and $stderrBuf.Length -gt 0) {
                    $exitResult.stderr = $stderrBuf.ToString()
                }
                return $exitResult
            }
            finally {
                $reader.Dispose()
                $streamObj.Dispose()
            }
        }
        finally {
            $resp.Dispose()
        }
    }
    finally {
        $cts.Dispose()
        $req.Dispose()
    }
}

function Invoke-InstaboxFileUpload {
    [CmdletBinding()]
    param(
        [string]$MachineId,
        [string]$RemotePath,
        [string]$Mode,
        [switch]$Parents,
        [string]$Token,
        [string]$SignedUploadUrl,
        [System.IO.Stream]$InputStream,
        [string]$ExpectedSha256
    )

    $sem = Get-InstaboxFsSemaphore
    $sem.Wait()
    try {
        $cfg = Get-InstaboxConfigInternal
        $baseUrl = ([string]$cfg.ApiBaseUrl).TrimEnd('/')

        if (-not [string]::IsNullOrWhiteSpace($SignedUploadUrl)) {
            $uriStr = $SignedUploadUrl
            $authMode = 'None'
        }
        else {
            $q = [System.Collections.Generic.List[string]]::new()
            $q.Add("path=$([Uri]::EscapeDataString($RemotePath))")
            if (-not [string]::IsNullOrWhiteSpace($Mode)) {
                $q.Add("mode=$([Uri]::EscapeDataString($Mode))")
            }
            if ($Parents) {
                $q.Add("parents=true")
            }
            if (-not [string]::IsNullOrWhiteSpace($Token)) {
                $q.Add("token=$([Uri]::EscapeDataString($Token))")
                $authMode = 'None'
            }
            else {
                $authMode = 'Default'
            }
            $uriStr = "$baseUrl/v1/machines/$([Uri]::EscapeDataString($MachineId))/files?$($q -join '&')"
        }

        $client = Get-InstaboxHttpClient
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Put, $uriStr)
        $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(7200))

        try {
            Add-InstaboxAuthHeader -Request $req -AuthMode $authMode
            $req.Headers.Accept.ParseAdd('application/json')
            $content = [System.Net.Http.StreamContent]::new($InputStream)
            $content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new('application/octet-stream')
            if ($InputStream.CanSeek) {
                $content.Headers.ContentLength = $InputStream.Length
            }
            $req.Content = $content

            Write-InstaboxLog -Level 'DEBUG' -Message "HTTP PUT $uriStr"
            $resp = $client.SendAsync($req, $cts.Token).GetAwaiter().GetResult()
            try {
                $statusCode = [int]$resp.StatusCode
                $respBody = $resp.Content.ReadAsStringAsync($cts.Token).GetAwaiter().GetResult()
                if (-not $resp.IsSuccessStatusCode) {
                    $retryHdr = Get-InstaboxRetryAfterHeader -Response $resp
                    throw (ConvertFrom-InstaboxErrorJson -StatusCode $statusCode -RawBody $respBody -HeaderRetryAfter $retryHdr)
                }
                $written = $respBody | ConvertFrom-Json -Depth 10
                if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256) -and $written.sha256) {
                    if ($written.sha256.ToLowerInvariant() -ne $ExpectedSha256.ToLowerInvariant()) {
                        throw [System.IO.InvalidDataException]::new("Upload SHA-256 mismatch! Expected $ExpectedSha256, server reported $($written.sha256).")
                    }
                }
                return $written
            }
            finally {
                $resp.Dispose()
            }
        }
        finally {
            $cts.Dispose()
            $req.Dispose()
        }
    }
    finally {
        [void]$sem.Release()
    }
}

function Invoke-InstaboxFileDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$MachineId,

        [Parameter(Mandatory)]
        [string]$RemotePath,

        [string]$LocalPath,

        [switch]$Resume,

        [int]$MaxResumeAttempts = 3
    )

    $sem = Get-InstaboxFsSemaphore
    $sem.Wait()
    try {
        $cfg = Get-InstaboxConfigInternal
        $baseUrl = ([string]$cfg.ApiBaseUrl).TrimEnd('/')
        $uriStr = "$baseUrl/v1/machines/$([Uri]::EscapeDataString($MachineId))/files/content?path=$([Uri]::EscapeDataString($RemotePath))"
        $client = Get-InstaboxHttpClient

        $etag = $null
        $offset = 0L
        $resolvedRemotePath = $RemotePath
        $fileMode = ''

        if ($Resume -and -not [string]::IsNullOrWhiteSpace($LocalPath) -and (Test-Path -LiteralPath $LocalPath)) {
            $offset = (Get-Item -LiteralPath $LocalPath).Length
        }

        $attempt = 0
        while ($true) {
            $attempt++
            $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $uriStr)
            $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(7200))
            try {
                Add-InstaboxAuthHeader -Request $req
                if ($offset -gt 0) {
                    $req.Headers.TryAddWithoutValidation('Range', "bytes=$offset-") | Out-Null
                    if (-not [string]::IsNullOrWhiteSpace($etag)) {
                        $req.Headers.TryAddWithoutValidation('If-Range', $etag) | Out-Null
                    }
                }

                Write-InstaboxLog -Level 'DEBUG' -Message "HTTP GET $uriStr (offset=$offset, attempt=$attempt)"
                $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token).GetAwaiter().GetResult()
                try {
                    $statusCode = [int]$resp.StatusCode
                    if (-not $resp.IsSuccessStatusCode) {
                        $errBody = $resp.Content.ReadAsStringAsync($cts.Token).GetAwaiter().GetResult()
                        $retryHdr = Get-InstaboxRetryAfterHeader -Response $resp
                        throw (ConvertFrom-InstaboxErrorJson -StatusCode $statusCode -RawBody $errBody -HeaderRetryAfter $retryHdr)
                    }

                    $vals = $null
                    if ($resp.Headers.TryGetValues('X-Instabox-File-Path', [ref]$vals)) {
                        $resolvedRemotePath = [Uri]::UnescapeDataString(($vals | Select-Object -First 1))
                    }
                    if ($resp.Headers.TryGetValues('X-Instabox-File-Mode', [ref]$vals)) {
                        $fileMode = ($vals | Select-Object -First 1)
                    }
                    if ($resp.Headers.ETag) {
                        $etag = $resp.Headers.ETag.ToString()
                    }
                    elseif ($resp.Headers.TryGetValues('ETag', [ref]$vals)) {
                        $etag = ($vals | Select-Object -First 1)
                    }

                    $expectedBytes = $resp.Content.Headers.ContentLength
                    $inStream = $resp.Content.ReadAsStreamAsync($cts.Token).GetAwaiter().GetResult()

                    try {
                        if ([string]::IsNullOrWhiteSpace($LocalPath)) {
                            $ms = [System.IO.MemoryStream]::new()
                            $inStream.CopyTo($ms)
                            return [PSCustomObject]@{
                                Path     = $resolvedRemotePath
                                Mode     = $fileMode
                                ETag     = $etag
                                Size     = $ms.Length
                                Bytes    = $ms.ToArray()
                            }
                        }

                        $parentDir = Split-Path -Parent $LocalPath
                        if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir)) {
                            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
                        }

                        # 200 resets file (e.g. file changed when If-Range didn't match); 206 appends
                        $fileModeOpen = if ($statusCode -eq 206) { [System.IO.FileMode]::Append } else { [System.IO.FileMode]::Create }
                        $bytesCopied = 0L
                        $fs = [System.IO.FileStream]::new($LocalPath, $fileModeOpen, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                        try {
                            $buf = New-Object byte[] 65536
                            while (($read = $inStream.Read($buf, 0, $buf.Length)) -gt 0) {
                                $fs.Write($buf, 0, $read)
                                $bytesCopied += $read
                            }
                        }
                        finally {
                            $fs.Dispose()
                        }

                        if ($null -ne $expectedBytes -and $bytesCopied -lt $expectedBytes -and $attempt -le $MaxResumeAttempts) {
                            $offset = (Get-Item -LiteralPath $LocalPath).Length
                            Write-InstaboxLog -Level 'WARN' -Message "Download truncated ($bytesCopied of $expectedBytes); resuming at byte $offset"
                            continue
                        }
                        if ($null -ne $expectedBytes -and $bytesCopied -lt $expectedBytes) {
                            throw [System.IO.EndOfStreamException]::new("Download interrupted after $bytesCopied of $expectedBytes bytes.")
                        }

                        $fi = Get-Item -LiteralPath $LocalPath
                        return [PSCustomObject]@{
                            Path       = $resolvedRemotePath
                            LocalPath  = $fi.FullName
                            Mode       = $fileMode
                            ETag       = $etag
                            Size       = $fi.Length
                            Resumed    = ($statusCode -eq 206)
                        }
                    }
                    finally {
                        $inStream.Dispose()
                    }
                }
                finally {
                    $resp.Dispose()
                }
            }
            catch [System.IO.IOException] {
                if (-not [string]::IsNullOrWhiteSpace($LocalPath) -and (Test-Path -LiteralPath $LocalPath) -and $attempt -le $MaxResumeAttempts) {
                    $offset = (Get-Item -LiteralPath $LocalPath).Length
                    if ($offset -gt 0) {
                        Write-InstaboxLog -Level 'WARN' -Message "I/O interruption during download; resuming at byte $offset"
                        continue
                    }
                }
                throw
            }
            finally {
                $cts.Dispose()
                $req.Dispose()
            }
        }
    }
    finally {
        [void]$sem.Release()
    }
}
