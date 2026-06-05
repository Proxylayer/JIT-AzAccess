# Remove-ExpiredRules/run.ps1
#
# Timer trigger — runs every 5 minutes.
# Scans the JITRules Table Storage table for expired entries and removes
# the corresponding rule on the target resource, then deletes the table record.

param($Timer)

Import-Module "$PSScriptRoot/../Modules/JITHelpers/JITHelpers.psm1"  -Force
Import-Module "$PSScriptRoot/../Modules/JITTargets/JITTargets.psm1" -Force

$tableName = if ($env:JIT_TABLE_NAME) { $env:JIT_TABLE_NAME } else { 'JITRules' }

Write-Host "JIT cleanup started at $(Get-Date -Format u)"

#region ── Load expired records ───────────────────────────────────────────────

try {
    $cloudTable = Get-JITCloudTable -TableName $tableName
    $allRows    = Get-AzTableRow -Table $cloudTable
}
catch {
    Write-Error "JIT cleanup: failed to read table '$tableName' — $_"
    return
}

$now     = [DateTime]::UtcNow
$expired = $allRows | Where-Object {
    try   { [DateTime]::Parse($_.ExpiryUtc) -lt $now }
    catch { $false }
}

if (-not $expired) {
    Write-Host "JIT cleanup: no expired rules found."
    return
}

Write-Host "JIT cleanup: found $($expired.Count) expired rule(s) to remove."

#endregion

#region ── Remove each expired rule ──────────────────────────────────────────

foreach ($row in $expired) {
    $label   = "'$($row.RuleIdentifier)' ($($row.TargetType)) on '$($row.ResourceName)' (expired $($row.ExpiryUtc))"
    $removed = $false

    try {
        switch ($row.TargetType) {
            'nsg'            { Remove-JITNsgRule            -Row $row }
            'sqlServer'      { Remove-JITSqlFirewallRule     -Row $row }
            'storageAccount' { Remove-JITStorageNetworkRule  -Row $row }
            'keyVault'       { Remove-JITKeyVaultNetworkRule -Row $row }
            default          {
                Write-Warning "  Unknown targetType '$($row.TargetType)' — skipping removal, deleting stale record."
            }
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
            Remove-AzTableRow -Table $cloudTable -PartitionKey $row.PartitionKey -RowKey $row.RowKey | Out-Null
            Write-Host "  Deleted table record for $($row.RowKey)"
        }
        catch {
            Write-Warning "  Rule was removed but table record deletion failed for $($row.RowKey) — $_"
        }
    }
}

#endregion

Write-Host "JIT cleanup complete."
