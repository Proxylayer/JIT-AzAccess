# Remove-ExpiredRules/run.ps1
#
# Timer trigger — runs every 5 minutes.
# Scans the JITRules Table Storage table for expired entries and removes
# the corresponding rule on the target resource, then deletes the table record.

param($Timer)

Import-Module "$PSScriptRoot/../Modules/HttpHelpers/HttpHelpers.psm1" -Force -DisableNameChecking
Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"   -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1"   -Force

$tableName = if ($env:JIT_TABLE_NAME) { $env:JIT_TABLE_NAME } else { 'JITRules' }

# A removal that keeps failing used to retry every 5 minutes forever with no
# counter, no escalation and no alert - so an open firewall hole looked exactly
# like a healthy system. Past this many consecutive failures the row is
# reported as JITRemoveStuck (alert on it; see azuredeploy.json).
$stuckThreshold = if ($env:JIT_REMOVE_STUCK_THRESHOLD) { [int]$env:JIT_REMOVE_STUCK_THRESHOLD } else { 12 }

# The host kills a run at functionTimeout (host.json: 9 minutes). A single
# removal can poll a long-running ARM operation for 180-300s, so a handful of
# slow ones used to get the run killed MID-ROW. Stop at ~80% of the budget and
# say what was deferred; the next tick picks the rest up.
$budgetSeconds = if ($env:JIT_CLEANUP_BUDGET_SECONDS) { [int]$env:JIT_CLEANUP_BUDGET_SECONDS } else { 430 }
$deadline      = [DateTime]::UtcNow.AddSeconds($budgetSeconds)

# Consecutive-failure count carried on the row itself.
function script:Get-RowRemoveAttempts {
    param($Row)
    $n = 0
    $raw = $Row.RemoveAttempts
    if ($null -ne $raw) { [void][int]::TryParse("$raw", [ref]$n) }
    return $n
}

# Records one failed removal attempt on the row and escalates once the count
# crosses the threshold. Never throws - the caller is already on a failure path.
function script:Register-RemoveFailure {
    param($Row, [string]$Label, [hashtable]$Extra = @{})

    $attempts = (Get-RowRemoveAttempts $Row) + 1
    try {
        Update-JITTableRow -TableName $tableName `
            -PartitionKey $Row.PartitionKey -RowKey $Row.RowKey `
            -Properties @{ RemoveAttempts = $attempts }
    }
    catch {
        Write-Warning "  Could not record RemoveAttempts=$attempts for $($Row.RowKey) - $_"
    }

    if ($attempts -ge $stuckThreshold) {
        $stuckExtra = @{ removeAttempts = $attempts; threshold = $stuckThreshold }
        foreach ($k in $Extra.Keys) { $stuckExtra[$k] = $Extra[$k] }
        Write-JITAuditEvent -EventType JITRemoveStuck `
            -Caller $Row.RequestedBy -CallerIp $Row.CallerIp `
            -TargetType $Row.TargetType -ResourceName $Row.ResourceName `
            -ResourceGroup $Row.ResourceRg -SubscriptionId $Row.SubscriptionId `
            -RuleId $Row.RowKey -Extra $stuckExtra
        Write-Error ("JIT STUCK: $Label has failed removal $attempts time(s). The IP is still " +
                     "allowed on the resource and the rule has outlived its expiry. Investigate.")
    }
    return $attempts
}

Write-Host "JIT cleanup started at $(Get-Date -Format u)"

#region ── Load expired records ───────────────────────────────────────────────

try {
    Get-JITTableName -TableName $tableName | Out-Null
    $allRows    = Get-JITTableRows -TableName $tableName
}
catch {
    Write-Error "JIT cleanup: failed to read table '$tableName' — $_"
    return
}

$now     = [DateTime]::UtcNow
$expired = $allRows | Where-Object {
    $e = ConvertTo-JITUtc $_.ExpiryUtc
    # Unparseable expiry: leave the row alone rather than guess. It surfaces
    # as a row that never clears, which is visible, instead of a rule revoked
    # early or one deleted without being revoked.
    $e -and $e -lt $now
}

if (-not $expired) {
    Write-Host "JIT cleanup: no expired rules found."
    return
}

Write-Host "JIT cleanup: found $($expired.Count) expired rule(s) to remove."

#endregion

#region ── Remove each expired rule ──────────────────────────────────────────

# Single source of truth (Modules/JITTargets). Keeping a second hand-written
# copy here is how a type ends up accepted for grant but unknown at expiry.
$supportedTypes = Get-JITSupportedTargetTypes

$deferred = 0

foreach ($row in $expired) {
    # Out of budget: leave the rest for the next tick rather than be killed
    # part-way through a removal.
    if ([DateTime]::UtcNow -ge $deadline) { $deferred++; continue }

    # Scoped per iteration: this used to persist across the loop, so the outer
    # catch could read the PREVIOUS row's result and attribute one resource's
    # state to another.
    $removeResult = $null

    $label = "'$($row.RuleIdentifier)' ($($row.TargetType)) on '$($row.ResourceName)' (expired $($row.ExpiryUtc))"

    # Unknown type — we can't act on the resource, but the record is expired and
    # unactionable, so delete it (don't retry forever) without a misleading
    # "expired/removed" audit event.
    if ($row.TargetType -notin $supportedTypes) {
        Write-Warning "  Unknown targetType '$($row.TargetType)' for $($row.RowKey) — deleting stale record without resource cleanup."
        try   { Remove-JITTableRow -TableName $tableName -PartitionKey $row.PartitionKey -RowKey $row.RowKey }
        catch { Write-Warning "  Failed to delete stale record $($row.RowKey) — $_" }
        continue
    }

    $removed = $false
    try {
        $removeResult = switch ($row.TargetType) {
            'nsg'                      { Remove-JITNsgRule                  -Row $row }
            'sqlServer'                { Remove-JITSqlFirewallRule          -Row $row }
            'postgresqlFlexibleServer' { Remove-JITPostgresFirewallRule     -Row $row }
            'storageAccount'           { Remove-JITStorageNetworkRule       -Row $row }
            'keyVault'                 { Remove-JITKeyVaultNetworkRule      -Row $row }
            'mysqlFlexibleServer'      { Remove-JITMysqlFlexibleServerRule  -Row $row }
            'redis'                    { Remove-JITRedisRule                -Row $row }
            'synapse'                  { Remove-JITSynapseRule              -Row $row }
            'cosmosDb'                 { Remove-JITCosmosDbRule             -Row $row }
            'containerRegistry'        { Remove-JITContainerRegistryRule    -Row $row }
            'aiSearch'                 { Remove-JITAiSearchRule             -Row $row }
            'cognitiveServices'        { Remove-JITCognitiveServicesRule    -Row $row }
            'kusto'                    { Remove-JITKustoRule                -Row $row }
            'iotHub'                   { Remove-JITIotHubRule               -Row $row }
            'signalR'                  { Remove-JITSignalRRule              -Row $row }
            'eventHub'                 { Remove-JITEventHubRule             -Row $row }
            'serviceBus'               { Remove-JITServiceBusRule           -Row $row }
            'appService'               { Remove-JITAppServiceRule           -Row $row }
            'aks'                      { Remove-JITAksRule                  -Row $row }
            default {
                # Reached only if a type is in Get-JITSupportedTargetTypes but
                # has no arm here. Throwing routes it to the catch below, which
                # KEEPS the row and audits - the silent alternative is falling
                # through with a null result, being treated as 'Removed', and
                # deleting the tracking row for a rule still on the resource.
                throw "No removal handler wired for supported targetType '$($row.TargetType)'."
            }
        }

        # Remove handlers return a Status: Removed | NotFound | Refused. A handler
        # that returns no Status (unexpected/legacy) is treated as Removed.
        $removeStatus = if ($removeResult -and $removeResult.Status) { $removeResult.Status } else { 'Removed' }
        # Per-resource outcome detail from the handler (App Service reports the
        # site plus every deployment slot, and flags a slot enumeration failure).
        # Carried onto the audit rows below so a partial removal is auditable
        # rather than visible only as a warning in the function logs.
        $removeDetails = if ($removeResult) { $removeResult.Details } else { $null }

        if ($removeStatus -eq 'Refused') {
            # AKS only: removing this IP would empty authorizedIPRanges and open
            # the API server, so the handler refused. Keep the table record so the
            # IP stays tracked/visible and is retried next cycle — do NOT delete.
            Write-Warning "  Refused to remove $label — would open the API server to the internet. Table record retained."
            Write-JITAuditEvent -EventType JITRemoveFailed `
                -TargetType $row.TargetType -ResourceName $row.ResourceName `
                -ResourceGroup $row.ResourceRg -SubscriptionId $row.SubscriptionId `
                -RuleId $row.RowKey -CallerIp $row.CallerIp `
                -Extra @{ reason = 'refused-would-open-cluster' }
            try {
                Add-JITAuditRow -Action 'RemoveFailed' `
                    -SubscriptionId $row.SubscriptionId -TargetType $row.TargetType `
                    -ResourceName $row.ResourceName -ResourceRg $row.ResourceRg `
                    -RuleIdentifier $row.RuleIdentifier -CallerIp $row.CallerIp `
                    -Port $row.Port -RequestedBy $row.RequestedBy `
                    -ExpiryUtc $row.ExpiryUtc -Justification $row.Justification `
                    -Extra @{ reason = 'refused-would-open-cluster' } `
                    -Details $removeDetails
            }
            catch {
                Write-Warning "  JITRulesAudit write failed for refused removal of ${label}: $_"
            }
            Register-RemoveFailure -Row $row -Label $label -Extra @{ reason = 'refused-would-open-cluster' } | Out-Null
            # $removed stays $false — the record is intentionally preserved.
        }
        else {
            # Removed OR NotFound — the rule is gone from the resource (either we
            # removed it, or the user deleted it manually). Either way, clean up
            # the stale tracking row below.
            $notFound = ($removeStatus -eq 'NotFound')
            Write-Host "  Removed $label"
            Write-JITAuditEvent -EventType JITExpired `
                -TargetType $row.TargetType -ResourceName $row.ResourceName `
                -ResourceGroup $row.ResourceRg -SubscriptionId $row.SubscriptionId `
                -RuleId $row.RowKey -CallerIp $row.CallerIp -Caller $row.RequestedBy `
                -Extra @{ notFound = $notFound }
            # Best-effort JITRulesAudit history row — a write failure here must NEVER
            # prevent the JITRules table record deletion below.
            try {
                $expireExtra = if ($notFound) { @{ notFound = $true } } else { @{} }
                Add-JITAuditRow -Action 'Expire' `
                    -SubscriptionId $row.SubscriptionId -TargetType $row.TargetType `
                    -ResourceName $row.ResourceName -ResourceRg $row.ResourceRg `
                    -RuleIdentifier $row.RuleIdentifier -CallerIp $row.CallerIp `
                    -Port $row.Port -RequestedBy $row.RequestedBy `
                    -ExpiryUtc $row.ExpiryUtc -Justification $row.Justification `
                    -Extra $expireExtra `
                    -Details $removeDetails
            }
            catch {
                Write-Warning "  JITRulesAudit write failed for expire of $label (removal itself succeeded): $_"
            }
            $removed = $true
        }
    }
    catch {
        Write-Warning "  Failed to remove $label — $_"
        Write-JITAuditEvent -EventType JITRemoveFailed `
            -TargetType $row.TargetType -ResourceName $row.ResourceName `
            -ResourceGroup $row.ResourceRg -SubscriptionId $row.SubscriptionId `
            -RuleId $row.RowKey -Extra @{ error = $_.ToString() }
        # Best-effort JITRulesAudit history row — must NEVER throw on the failure
        # path (the table record is intentionally left for retry regardless).
        try {
            Add-JITAuditRow -Action 'RemoveFailed' `
                -SubscriptionId $row.SubscriptionId -TargetType $row.TargetType `
                -ResourceName $row.ResourceName -ResourceRg $row.ResourceRg `
                -RuleIdentifier $row.RuleIdentifier -CallerIp $row.CallerIp `
                -Port $row.Port -RequestedBy $row.RequestedBy `
                -ExpiryUtc $row.ExpiryUtc -Justification $row.Justification `
                -Extra @{ error = $_.ToString() }
        }
        catch {
            Write-Warning "  JITRulesAudit write failed for remove-failure of ${label}: $_"
        }
        Register-RemoveFailure -Row $row -Label $label -Extra @{ error = $_.ToString() } | Out-Null
        # Leave the table record so we retry on the next tick.
    }

    if ($removed) {
        try {
            Remove-JITTableRow -TableName $tableName -PartitionKey $row.PartitionKey -RowKey $row.RowKey
            Write-Host "  Deleted table record for $($row.RowKey)"
        }
        catch {
            Write-Warning "  Rule was removed but table record deletion failed for $($row.RowKey) — $_"
        }
    }
}

#endregion

if ($deferred -gt 0) {
    Write-Warning ("JIT cleanup: ran out of time budget (${budgetSeconds}s) with $deferred expired " +
                   "rule(s) not yet attempted. They will be retried on the next tick.")
}

Write-Host "JIT cleanup complete."
