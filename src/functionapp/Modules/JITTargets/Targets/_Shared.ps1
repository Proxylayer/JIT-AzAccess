# _Shared.ps1
# Cross-type helpers for the JITTargets module.
#
# This file is dot-sourced FIRST by JITTargets.psm1, so everything defined here
# lands in the module scope and is visible to every per-type file that follows.
# Only genuinely cross-type helpers live here — the ConvertTo-Hashtable clone
# (used by Storage and Key Vault), the Get-HeaderValue lookup, and the generic
# ARM long-running-operation poller. Per-type constants (ARM API versions, the
# PostgreSQL LRO bounds, the private-server sentinel) live in their own type
# files so each type's configuration is co-located with its handler.

function script:ConvertTo-Hashtable {
    # Shallow-clones a PSCustomObject (e.g. from Invoke-RestMethod) into a
    # hashtable so we can change ONE property and PATCH the whole object back,
    # preserving every other field. Critical for networkAcls: a PATCH that
    # sends only ipRules resets defaultAction/bypass/virtualNetworkRules to
    # ARM defaults — which can flip a resource to public. We never want that.
    param($InputObject)
    $h = @{}
    if ($null -eq $InputObject) { return $h }
    foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = $p.Value }
    return $h
}

function script:Get-HeaderValue {
    # Case-insensitive lookup against the normalized header hashtable returned by
    # Invoke-ArmRestRaw (server casing is preserved, so match ordinal-ignorecase).
    param([hashtable]$Headers, [string]$Name)
    if (-not $Headers) { return $null }
    foreach ($k in $Headers.Keys) {
        if ([string]::Equals($k, $Name, [StringComparison]::OrdinalIgnoreCase)) { return $Headers[$k] }
    }
    return $null
}

function script:ConvertTo-JITIpv4Number {
    # Parses a dotted-quad IPv4 string into a comparable [int64] (big-endian
    # ordering, so numeric compare == address compare). Returns $null for
    # anything that is not a plain IPv4 address (IPv6, CIDR, garbage) — callers
    # treat $null as "can't compare" and fall back to their default behavior.
    param([string]$Ip)
    if (-not $Ip) { return $null }
    [System.Net.IPAddress]$addr = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return $null }
    if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }
    $b = $addr.GetAddressBytes()   # network order (big-endian)
    return ([int64]$b[0] -shl 24) -bor ([int64]$b[1] -shl 16) -bor ([int64]$b[2] -shl 8) -bor [int64]$b[3]
}

function script:Test-JITFirewallRuleCoversIp {
    # Best-effort "is this single IP already whitelisted by an existing
    # child firewall rule?" check for the SQL-style firewallRules types.
    # Given the collection GET's .value array (each item having a .properties
    # with start/end IP fields), returns $true when any rule's [start,end]
    # inclusive range covers the caller IP — so we never create a duplicate
    # rule for an IP an existing rule already allows.
    #
    # Field names differ per provider (SQL/PostgreSQL/MySQL/Synapse use
    # startIpAddress/endIpAddress; Redis uses startIP/endIP), so they are
    # passed in. Non-IPv4 caller IPs (or unparseable rule bounds) are treated
    # as "not covered" so the caller falls back to creating a rule.
    param(
        $Rules,
        [Parameter(Mandatory)][string]$CallerIp,
        [string]$StartField = 'startIpAddress',
        [string]$EndField   = 'endIpAddress'
    )
    $ipNum = ConvertTo-JITIpv4Number $CallerIp
    if ($null -eq $ipNum) { return $false }
    foreach ($r in @($Rules)) {
        $props = if ($r.properties) { $r.properties } else { $r }
        if (-not $props) { continue }
        $start = ConvertTo-JITIpv4Number ([string]$props.$StartField)
        $end   = ConvertTo-JITIpv4Number ([string]$props.$EndField)
        if ($null -eq $start -or $null -eq $end) { continue }
        if ($ipNum -ge $start -and $ipNum -le $end) { return $true }
    }
    return $false
}

function Wait-JITArmAsyncOperation {
    <#
    .SYNOPSIS
        Polls an Azure async (long-running) operation to completion.

    .DESCRIPTION
        Given the response headers from a 202 Accepted reply, GETs the
        Azure-AsyncOperation URL (falling back to Location) with the MI ARM
        token, honoring each response's Retry-After header between polls, until
        the operation JSON `status` is:
          • Succeeded            -> returns
          • Failed / Canceled    -> throws with the operation's error detail
          • (still running)       -> keeps polling
        or the overall timeout elapses (throws a timeout error).

    .PARAMETER ResponseHeaders
        The normalized header hashtable from the initiating 202 response
        (as returned by Invoke-ArmRestRaw).

    .PARAMETER TimeoutSeconds
        Overall cap on how long to keep polling before throwing a timeout.
        Callers pass their own bound; the default keeps this poller decoupled
        from any per-type constant.

    .PARAMETER DefaultPollSeconds
        Poll interval used when a response carries no usable Retry-After header.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$ResponseHeaders,
        [int]$TimeoutSeconds      = 180,
        [int]$DefaultPollSeconds  = 5
    )

    $asyncUrl = Get-HeaderValue $ResponseHeaders 'Azure-AsyncOperation'
    if (-not $asyncUrl) { $asyncUrl = Get-HeaderValue $ResponseHeaders 'Location' }
    if (-not $asyncUrl) {
        throw "Async operation returned 202 but no Azure-AsyncOperation or Location header to poll."
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $headers  = $ResponseHeaders
    $poll     = 0

    while ([DateTime]::UtcNow -lt $deadline) {
        # Honor Retry-After from the most recent response before the next poll;
        # clamp to a sane range so a bad header can't stall or busy-loop us.
        $retryAfter = Get-HeaderValue $headers 'Retry-After'
        $waitSec    = $DefaultPollSeconds
        if ($retryAfter -and ($retryAfter -match '^\d+$')) { $waitSec = [int]$retryAfter }
        if ($waitSec -lt 1)  { $waitSec = 1 }
        if ($waitSec -gt 30) { $waitSec = 30 }

        Start-Sleep -Seconds $waitSec
        $poll++

        $raw     = Invoke-ArmRestRaw -Path $asyncUrl -Method GET
        $headers = $raw.Headers
        $status  = $null
        if ($raw.Content) {
            try { $status = ($raw.Content | ConvertFrom-Json -ErrorAction Stop).status } catch { $status = $null }
        }

        Write-Host "  ARM LRO poll #$poll -> status=$status"

        switch ($status) {
            'Succeeded' { return }
            'Failed'    { throw "Async operation failed: $($raw.Content)" }
            'Canceled'  { throw "Async operation was canceled: $($raw.Content)" }
            'Cancelled' { throw "Async operation was canceled: $($raw.Content)" }
            default     { }   # InProgress / Running / Accepted / null — keep polling
        }
    }

    throw "Async operation did not complete within $TimeoutSeconds seconds (timeout)."
}

function Remove-JITChildRuleWithLro {
    <#
    .SYNOPSIS
        Idempotently deletes a child rule resource whose DELETE is long-running,
        returning 'Removed' or 'NotFound' and never failing merely because the
        rule was already gone.

    .DESCRIPTION
        Shared by the four target types whose firewall-rule DELETE is an LRO:
        PostgreSQL / MySQL flexible servers, Redis, and Synapse.

        The naive shape — DELETE, then poll — is not idempotent in practice.
        Deleting an ALREADY-ABSENT PostgreSQL firewall rule does not return 404:
        the resource provider accepts the request with 202 Accepted and then
        fails the async operation with a bare InternalServerError. A caller that
        trusts that error concludes the removal failed, keeps the JITRules row,
        and retries every five minutes forever, so a rule removed out-of-band
        (by an admin, another tool, or a partially-completed earlier run) strands
        its row permanently. Observed in production 2026-08-29.

        So this helper reconciles against reality rather than trusting the RP:

          1. GET the rule first. Absent -> 'NotFound', no DELETE attempted. This
             is the cheap path and avoids the broken behavior entirely.
          2. DELETE, polling if the reply is 202.
          3. If the poll throws, GET again. If the rule is now gone the delete
             actually succeeded (or someone else removed it concurrently), so
             report 'Removed'. Only a rule that is STILL PRESENT rethrows.

        Step 3 matters beyond this one RP bug: it also converts async timeouts
        into a correct answer whenever the underlying operation did complete.

    .PARAMETER Path
        Full ARM path of the child rule resource.

    .PARAMETER TypeLabel
        Human-readable resource type used in log lines (e.g. 'PostgreSQL').
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ApiVersion,
        [Parameter(Mandatory)][string]$RuleName,
        [string]$TypeLabel          = 'firewall rule',
        [int]   $TimeoutSeconds     = 180,
        [int]   $DefaultPollSeconds = 5
    )

    # Returns $true / $false, or $null when existence could not be determined
    # (a transport failure, say) — the caller must not treat unknown as absent.
    $ruleExists = {
        try {
            Invoke-ArmRestRaw -Method GET -Path $Path -ApiVersion $ApiVersion | Out-Null
            return $true
        }
        catch {
            if ((Get-StatusFromError $_) -eq 404) { return $false }
            return $null
        }
    }

    if ((& $ruleExists) -eq $false) {
        Write-Host "  $TypeLabel rule '$RuleName' not found — already removed."
        return @{ Status = 'NotFound'; Details = @{} }
    }

    try {
        $resp = Invoke-ArmRestRaw -Method DELETE -Path $Path -ApiVersion $ApiVersion
        if ($resp.StatusCode -eq 202) {
            Wait-JITArmAsyncOperation -ResponseHeaders $resp.Headers `
                -TimeoutSeconds     $TimeoutSeconds `
                -DefaultPollSeconds $DefaultPollSeconds
        }
        return @{ Status = 'Removed'; Details = @{} }
    }
    catch {
        if ((Get-StatusFromError $_) -eq 404) {
            Write-Host "  $TypeLabel rule '$RuleName' not found — already removed."
            return @{ Status = 'NotFound'; Details = @{} }
        }

        # The delete reported failure. Believe the resource, not the report.
        if ((& $ruleExists) -eq $false) {
            Write-Warning "  $TypeLabel rule '$RuleName': delete reported failure but the rule is gone — treating as removed. $($_.Exception.Message)"
            return @{ Status = 'Removed'; Details = @{ reconciled = $true; reportedError = $_.Exception.Message } }
        }

        throw
    }
}

function Invoke-JITArmReadModifyWrite {
    <#
    .SYNOPSIS
        Optimistic-concurrency read-modify-write for ARM resources whose IP
        allowlist is an ARRAY on the resource (or on a networkRuleSets/default
        child), rather than an independently addressable child rule.

    .DESCRIPTION
        Array-on-resource grants are RACE-PRONE: two concurrent JIT grants that
        both GET the resource, add their IP, and write back will have the second
        write silently drop the first IP (last-writer-wins). This helper isolates
        the fix so every array-type handler reuses it:

          1. GET the resource via Invoke-ArmRestRaw, capturing its ETag.
          2. Run the caller's -Modify scriptblock with the deserialized resource.
             The block inspects the current state (including sibling properties)
             and RETURNS the request body to write — either the whole mutated
             resource (for PUT/full-replace types) or a minimal object such as
             { properties = @{ networkAcls = <full acl> } } (for PATCH types
             whose update schema rejects unrelated read-only fields). Returning
             the full container sub-object is what preserves defaultAction,
             bypass, privateEndpoints etc. — a partial write that omits them
             would reset the resource's posture, which we must never do.
          3. Write the returned body (PATCH or PUT per -WriteMethod) with
             `If-Match: <etag>` (when the GET returned an ETag). ARM rejects a
             stale write with 412 Precondition Failed; we then re-GET and retry
             (bounded by -MaxAttempts). When the resource type returns no ETag,
             the write degrades gracefully to last-writer-wins.
          4. If the write is long-running (202 Accepted), poll to completion via
             Wait-JITArmAsyncOperation.

        The -Modify scriptblock returns $false to signal "no change needed"
        (e.g. IP already present on grant, already absent on removal, or the
        resource is not network-restricted); the helper then returns without
        writing — keeping grant/removal idempotent.

    .PARAMETER Path
        ARM resource path to GET and write back (no api-version — it is added).

    .PARAMETER ApiVersion
        Per-type ARM api-version.

    .PARAMETER Modify
        Scriptblock: param($resource) { ... }. Receives the deserialized
        resource object and returns the request body to write, or $false to
        skip the write entirely.

    .PARAMETER WriteMethod
        PATCH (default) or PUT for the write-back, per the resource type's API.

    .PARAMETER MaxAttempts
        Bound on re-read/retry cycles when the write keeps losing the 412 race.

    .PARAMETER LroTimeoutSeconds / LroDefaultPollSeconds
        Passed through to Wait-JITArmAsyncOperation for 202 write-backs.

    .OUTPUTS
        Hashtable @{ Changed = <bool> } — $false when the -Modify block skipped.
    #>
    param(
        [Parameter(Mandatory)][string]      $Path,
        [Parameter(Mandatory)][string]      $ApiVersion,
        [Parameter(Mandatory)][scriptblock] $Modify,
        [ValidateSet('PATCH', 'PUT')][string] $WriteMethod = 'PATCH',
        [int] $MaxAttempts           = 5,
        [int] $LroTimeoutSeconds     = 180,
        [int] $LroDefaultPollSeconds = 5
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {

        # ── 1. GET current resource + ETag ────────────────────────────────────
        $getResp  = Invoke-ArmRestRaw -Method GET -Path $Path -ApiVersion $ApiVersion
        $resource = if ($getResp.Content) { $getResp.Content | ConvertFrom-Json } else { $null }
        $etag     = Get-HeaderValue $getResp.Headers 'ETag'

        # ── 2. Caller inspects/mutates and returns the body to write ──────────
        # $false (explicit) => nothing to do (idempotent). Guard against stray
        # pipeline output by inspecting only the last emitted value.
        $body = & $Modify $resource
        if ($body -is [System.Array] -and $body.Count -gt 0) { $body = $body[-1] }
        if ($body -is [bool] -and -not $body) {
            return @{ Changed = $false }
        }

        # ── 3. Conditional write-back (If-Match for optimistic concurrency) ────
        $headers = @{}
        if ($etag) { $headers['If-Match'] = $etag }

        try {
            $writeResp = Invoke-ArmRestRaw -Method $WriteMethod -Path $Path `
                -ApiVersion $ApiVersion -Body $body -ExtraHeaders $headers

            # ── 4. Poll if the write is long-running ──────────────────────────
            # Two LRO flavors across these RPs: a classic 202 Accepted, and a
            # 200/201 that still carries an Azure-AsyncOperation header (ACR,
            # Cosmos, Cognitive Services, IoT Hub do this). Poll in both cases;
            # a truly synchronous 200 with no such header falls straight through.
            $asyncHeader = Get-HeaderValue $writeResp.Headers 'Azure-AsyncOperation'
            if ($writeResp.StatusCode -eq 202 -or $asyncHeader) {
                Wait-JITArmAsyncOperation -ResponseHeaders $writeResp.Headers `
                    -TimeoutSeconds     $LroTimeoutSeconds `
                    -DefaultPollSeconds $LroDefaultPollSeconds
            }
            return @{ Changed = $true }
        }
        catch {
            $status = Get-StatusFromError $_
            if ($status -eq 412 -and $attempt -lt $MaxAttempts) {
                Write-Host "  ARM RMW precondition failed (412) on attempt $attempt/$MaxAttempts — re-reading and retrying."
                continue
            }
            throw
        }
    }

    throw "ARM read-modify-write on '$Path' did not converge after $MaxAttempts attempts (persistent 412 conflict)."
}
