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
    try   { [DateTimeOffset]::Parse($_.ExpiryUtc).UtcDateTime -lt $now }
    catch { $false }
}

if (-not $expired) {
    Write-Host "JIT cleanup: no expired rules found."
    return
}

Write-Host "JIT cleanup: found $($expired.Count) expired rule(s) to remove."

#endregion

#region ── Remove each expired rule ──────────────────────────────────────────

$supportedTypes = @(
    'nsg', 'sqlServer', 'postgresqlFlexibleServer', 'storageAccount', 'keyVault',
    'mysqlFlexibleServer', 'redis', 'synapse', 'cosmosDb', 'containerRegistry',
    'aiSearch', 'cognitiveServices', 'kusto', 'iotHub', 'signalR',
    'eventHub', 'serviceBus', 'appService', 'aks'
)

foreach ($row in $expired) {
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

Write-Host "JIT cleanup complete."
