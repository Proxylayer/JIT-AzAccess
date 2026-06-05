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

$supportedTypes = @('nsg', 'sqlServer', 'storageAccount', 'keyVault')

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
        switch ($row.TargetType) {
            'nsg'            { Remove-JITNsgRule            -Row $row }
            'sqlServer'      { Remove-JITSqlFirewallRule     -Row $row }
            'storageAccount' { Remove-JITStorageNetworkRule  -Row $row }
            'keyVault'       { Remove-JITKeyVaultNetworkRule -Row $row }
        }
        Write-Host "  Removed $label"
        Write-JITAuditEvent -EventType JITExpired `
            -TargetType $row.TargetType -ResourceName $row.ResourceName `
            -ResourceGroup $row.ResourceRg -SubscriptionId $row.SubscriptionId `
            -RuleId $row.RowKey -CallerIp $row.CallerIp -Caller $row.RequestedBy
        $removed = $true
    }
    catch {
        Write-Warning "  Failed to remove $label — $_"
        Write-JITAuditEvent -EventType JITRemoveFailed `
            -TargetType $row.TargetType -ResourceName $row.ResourceName `
            -ResourceGroup $row.ResourceRg -SubscriptionId $row.SubscriptionId `
            -RuleId $row.RowKey -Extra @{ error = $_.ToString() }
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
