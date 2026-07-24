# Aks.ps1
#region ── Azure Kubernetes Service (Microsoft.ContainerService/managedClusters) ─
# https://learn.microsoft.com/rest/api/aks/managed-clusters/create-or-update
#
# The API-server IP allowlist is a BARE STRING array of CIDRs at
# properties.apiServerAccessProfile.authorizedIPRanges[]. There is NO PATCH for
# cluster properties, so a grant is a full-body read-modify-PUT: GET the cluster,
# mutate ONLY that array, PUT the WHOLE cluster back (preserving every other
# apiServerAccessProfile field — enablePrivateCluster, disableRunCommand,
# enableVnetIntegration, subnetId, privateDNSZone — and the rest of the
# resource). The PUT is long-running; the shared RMW helper polls to completion.
#
# TWO CRITICAL SAFETY GUARDS:
#   (a) REJECT private clusters. When enablePrivateCluster == true, authorized IP
#       ranges do not apply at all, so a grant can never help. We throw a
#       sentinel-prefixed error (same $PRIVATE_SERVER_REJECTED: prefix the
#       PostgreSQL handler uses) so Request-JITAccess surfaces a clean 409.
#   (b) NEVER WRITE AN EMPTY authorizedIPRanges ARRAY. An empty array means the
#       API server is OPEN TO THE ENTIRE INTERNET. Consequences:
#         • ADD: if the array is currently empty the cluster is already open, so
#           we do NOT create the first restriction (that would lock the API
#           server down to only the caller's IP) — mirrors the Kusto/Storage
#           "never restrict an already-open resource" guard.
#         • REMOVE: if removing the caller's IP would empty the array, we leave
#           the cluster UNCHANGED rather than write an empty array — refusing to
#           open the API server is the single most important AKS safety rule.
#
# RuleIdentifier stored = the caller IP (like the other string-array types).

# ── ARM API version ───────────────────────────────────────────────────────────
$script:AksApi = '2025-05-01'   # Microsoft.ContainerService/managedClusters

# ── Private-cluster rejection sentinel ────────────────────────────────────────
# Same literal prefix as the PostgreSQL private-server sentinel so the existing
# catch in Request-JITAccess/run.ps1 ('PRIVATE_SERVER_REJECTED:*') surfaces both
# as a clean 409 + JITDenied audit event instead of a generic 500.
$script:AksPrivateRejectPrefix = 'PRIVATE_SERVER_REJECTED:'

# ── LRO poll bounds ───────────────────────────────────────────────────────────
# Cluster PUT for an authorized-IP-range change completes quickly, but the cap
# protects the synchronous HTTP request / timer worker from hanging.
$script:AksLroTimeoutSeconds     = 300
$script:AksLroDefaultPollSeconds = 10

function Add-JITAksRule {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$CallerIp,
        [Parameter(Mandatory)][string]$RuleId
    )

    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
            "/providers/Microsoft.ContainerService/managedClusters/$ResourceName"

    # Distinguishes the two no-write outcomes (SkippedOpen = API server open /
    # unrestricted; AlreadyPresent = caller IP already authorized).
    $outcome = @{ Reason = 'SkippedOpen' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:AksApi -WriteMethod PUT `
        -LroTimeoutSeconds $script:AksLroTimeoutSeconds `
        -LroDefaultPollSeconds $script:AksLroDefaultPollSeconds -Modify {
        param($resource)
        $accessProfile = if ($resource.properties) { $resource.properties.apiServerAccessProfile } else { $null }

        # Guard (a): private clusters can't use authorized IP ranges — reject.
        # This throw happens before any write and propagates to the dispatcher's
        # PRIVATE_SERVER_REJECTED catch (clean 409, not a 500).
        if ($accessProfile -and $accessProfile.enablePrivateCluster) {
            throw "$script:AksPrivateRejectPrefix AKS cluster '$ResourceName' is a private cluster; API-server authorized IP ranges do not apply."
        }

        $ranges = @()
        if ($accessProfile -and $accessProfile.authorizedIPRanges) { $ranges = @($accessProfile.authorizedIPRanges) }

        # Guard (b)/ADD: empty => API server is open. Do NOT create the first
        # restriction (that would lock everyone but this IP out).
        if ($ranges.Count -eq 0) { $outcome.Reason = 'SkippedOpen'; return $false }

        $cidr = "$CallerIp/32"
        if ($ranges -contains $cidr) { $outcome.Reason = 'AlreadyPresent'; return $false }   # already present

        # Full-body PUT: mutate ONLY authorizedIPRanges, preserve everything else.
        $resource.properties.apiServerAccessProfile.authorizedIPRanges = @($ranges) + @($cidr)
        return $resource
    }

    if (-not $r.Changed) {
        return @{ RuleIdentifier = $CallerIp; Status = $outcome.Reason; Details = @{ note = 'no change (cluster API server not IP-restricted, or IP already authorized)' } }
    }
    return @{ RuleIdentifier = $CallerIp; Status = 'Created'; Details = @{} }
}

function Remove-JITAksRule {
    param([Parameter(Mandatory)]$Row)

    $ipValue = if ($Row.RuleIdentifier) { $Row.RuleIdentifier } else { $Row.CallerIp }
    if (-not $ipValue) {
        Write-Warning "  AKS row has neither RuleIdentifier nor CallerIp — cannot identify authorized IP range to remove."
        return @{ Status = 'NotFound'; Details = @{ reason = 'no-identifier' } }
    }

    $path = "/subscriptions/$($Row.SubscriptionId)/resourceGroups/$($Row.ResourceRg)" +
            "/providers/Microsoft.ContainerService/managedClusters/$($Row.ResourceName)"

    # Set by the -Modify block to distinguish the no-write outcomes: 'NotFound'
    # (the IP was already gone / no ranges) vs 'Refused' (removing it would empty
    # the array and open the API server, so we intentionally leave it in place).
    $outcome = @{ Reason = 'NotFound' }

    $r = Invoke-JITArmReadModifyWrite -Path $path -ApiVersion $script:AksApi -WriteMethod PUT `
        -LroTimeoutSeconds $script:AksLroTimeoutSeconds `
        -LroDefaultPollSeconds $script:AksLroDefaultPollSeconds -Modify {
        param($resource)
        $accessProfile = if ($resource.properties) { $resource.properties.apiServerAccessProfile } else { $null }
        if (-not ($accessProfile -and $accessProfile.authorizedIPRanges)) { $outcome.Reason = 'NotFound'; return $false }   # nothing to remove

        $ranges    = @($accessProfile.authorizedIPRanges)
        # Match the '<ip>/32' form Add wrote, and a bare IP defensively.
        $remaining = @($ranges | Where-Object { $_ -ne "$ipValue/32" -and $_ -ne $ipValue })
        if ($remaining.Count -eq $ranges.Count) { $outcome.Reason = 'NotFound'; return $false }   # already gone (idempotent)

        # Guard (b)/REMOVE: never write an empty array — that opens the API server
        # to the whole internet. Leave the cluster unchanged instead.
        if ($remaining.Count -eq 0) {
            Write-Warning "  Refusing to remove the last authorized IP range on AKS cluster '$($resource.name)' — that would open the API server to the internet. Leaving cluster unchanged."
            $outcome.Reason = 'Refused'
            return $false
        }

        $resource.properties.apiServerAccessProfile.authorizedIPRanges = $remaining
        return $resource
    }

    if ($r.Changed) { return @{ Status = 'Removed'; Details = @{} } }
    return @{ Status = $outcome.Reason; Details = @{} }
}

#endregion
