# CloudHealth platform health model discovery via policy

A spike for [Azure/ahm-planning#3553](https://github.com/Azure/ahm-planning/issues/3553).

A `DeployIfNotExists` policy that creates one `Microsoft.CloudHealth/healthmodels` model with one discovery rule per ALZ platform domain:

- Security
- Connectivity
- Management
- Identity


> ALZ naming: the four domains match ALZ's platform management groups (Connectivity, Identity, Management, Security), see `modules/managementGroups/managementGroups.bicep`. The policy names each rule `discover-<domain>` (`discover-connectivity`, `discover-identity`, `discover-management`, `discover-security`).

## What is doesn't do
- currently only a single subscription is supported in the query per domain, I guess in reality you would have multiple
- in reality, maybe ALZ resources are found via the management group, that's not yet in the policy
- it uses a single authentication setting/identity for all four discovery rules


## Parameters

Each domain query is
- `resources | [where subscriptionId =~ '<sub>' |] where type in~ (<types>) | project id`
- where `<types>` is `includedResourceTypesGlobal` unioned with `<domain>ResourceTypes`.

The template adds the `subscriptionId` clause only when you set `<domain>SubscriptionId`.

A non-empty `<domain>QueryOverride` replaces the whole query.

| Parameter | Type | Purpose |
|---|---|---|
| `includedResourceTypesGlobal` | Array | Types added to every domain. Empty by default; a hook to inject one type everywhere. |
| `{security,connectivity,management,identity}ResourceTypes` | Array | Types for that domain, unioned with the global list. Ships with per-domain defaults. |
| `{security,...}SubscriptionId` | String (`''`) | Optional. Scopes that domain to one subscription. Empty spans every subscription the identity can read. |
| `{security,...}QueryOverride` | String (`''`) | Full query replacement for that domain. Empty auto-builds from the types and subscription id. |
| `effect`, `enforcementMode` | String | Standard policy knobs. |
| `targetResourceGroupName`, `healthModelName`, `identityName`, `location`, `policyName`, `assignmentName` | String | Placement and names. |

Four ways to drive it:

1. Deploy with defaults.
2. Add types to `includedResourceTypesGlobal` (all domains) or one `{domain}ResourceTypes`.
3. Pin a domain to a subscription with `{domain}SubscriptionId`.
4. Replace a domain query with `{domain}QueryOverride`.

## Which subscriptions get discovered

A rule without `{domain}SubscriptionId` returns resources from every subscription its identity can read, so RBAC breadth controls scope:

Set `{domain}SubscriptionId` when a domain lives in its own subscription (e.g. `identitySubscriptionId` for the Identity platform subscription).

## Usage example

(takes 15-20 minutes)

```bash
# 1. Create the target resource group                                  (~5 s)
az group create --name rg-alz-healthmodels --location uksouth

# 2. Deploy the policy, identity, and assignment                       (~1-2 min)
az deployment sub create \
  --name alz-cloudhealth \
  --location uksouth \
  --template-file healthmodel-policy.bicep \
  --parameters targetResourceGroupName=rg-alz-healthmodels

# 3. Evaluate compliance (on-demand scan)                              (~8-15 min)
az policy state trigger-scan --resource-group rg-alz-healthmodels

# 4. Remediate: the policy deploys the model, 4 discovery rules,
#    and 4 root relationships. The command returns fast; the
#    remediation deployment reaches Succeeded a few minutes later.     (~2-4 min)
az policy remediation create --name remediate-ahm \
  --policy-assignment "$(az policy assignment show --name Deploy-ALZ-CloudHealth --query id -o tsv)" \
  --resource-group rg-alz-healthmodels
```

Verify (each `az rest` call is ~2-5 s). Discovery runs on a ~5-minute cadence, so the entity count may read 0 for the first few minutes even after the rules show `Succeeded`. `Microsoft.CloudHealth` does not show up in `az resource list` or Resource Graph tooling, so query the resource provider with `az rest`:

```bash
SUB=$(az account show --query id -o tsv)

# List the four domain rules (each should be Succeeded)
az rest --method get \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-alz-healthmodels/providers/Microsoft.CloudHealth/healthmodels/alz-platform-healthmodel/discoveryrules?api-version=2026-05-01-preview" \
  --query "value[].{name:name, state:properties.provisioningState, query:properties.specification.resourceGraphQuery}" -o table

# Count discovered entities (expect a non-zero number)
az rest --method get \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-alz-healthmodels/providers/Microsoft.CloudHealth/healthmodels/alz-platform-healthmodel/entities?api-version=2026-05-01-preview" \
  --query "length(value)" -o tsv
```

Verified run: 4 rules `Succeeded` (`discover-security`, `discover-connectivity`, `discover-management`, `discover-identity`), 50 entities discovered.

## Remove everything

```bash
SUB=$(az account show --query id -o tsv)
ASSIGNMENT_MI=$(az policy assignment show --name Deploy-ALZ-CloudHealth --query identity.principalId -o tsv)
DISCOVERY_MI=$(az identity show -g rg-alz-healthmodels -n alz-healthmodel-mi --query principalId -o tsv)

# 1. Role assignments for both principals                              (~5-15 s total)
#    (Contributor, Managed Identity Operator, Reader)
for pid in "$ASSIGNMENT_MI" "$DISCOVERY_MI"; do
  for ra in $(az role assignment list --all --query "[?principalId=='$pid'].id" -o tsv); do
    az role assignment delete --ids "$ra"
  done
done

# 2. Remediation record, assignment, definition                       (~10-20 s total)
az policy remediation delete --name remediate-ahm --resource-group rg-alz-healthmodels
az policy assignment delete --name Deploy-ALZ-CloudHealth
az policy definition delete --name Deploy-ALZ-CloudHealth-PlatformModel

# 3. Health model (delete through the resource provider)              (~5 s to submit)
az rest --method delete \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-alz-healthmodels/providers/Microsoft.CloudHealth/healthmodels/alz-platform-healthmodel?api-version=2026-05-01-preview"

# 4. Resource group (also removes the discovery identity)             (~1-3 min)
az group delete --name rg-alz-healthmodels --yes
```

## Files

- `healthmodel-policy.bicep`: the file you deploy. Defines the DINE policy (embedded template builds the model, an authentication setting, four discovery rules, four root relationships), assigns it, grants the policy identity Contributor and Managed Identity Operator, and imports the identity module.
- `healthmodel-discovery-identity.bicep`: resource-group-scoped module for the user-assigned managed identity plus its Reader grant.

## Notes

- The DINE rule anchors on the target resource group, since the anchor must already exist. `existenceCondition` on the health model name decides compliance, so the model drives it, not the resource group.
- `addResourceHealthSignal` is fixed to `Enabled` in every rule, not a parameter.
- `Microsoft.CloudHealth` has no strong Bicep types, so `az bicep build` accepts invalid shapes. Confirm every change with a live deploy.
- Changing the parameter set is not an in-place definition update. Delete the assignment and definition, then redeploy.
- `ReEvaluateCompliance` remediation can stall, so the steps above use `trigger-scan` then the default remediation mode.

## Resource group ownership (open)

The policy deploys into an existing resource group and does not create it. Decide before production whether to use a dedicated `rg-<platform>-healthmodels` or a shared platform RG, and let the landing-zone platform deployment own the RG lifecycle.

## What didn't work as expected
The resource-type arrays are plain `Array` parameters (not `strongType: resourceTypes`) on purpose. `strongType: resourceTypes` makes the Azure portal render every such field with a fixed "Resource type" picker and ignore the parameter's `displayName`, so all four domains looked identical in the assignment blade. Dropping `strongType` lets the portal show each domain label (`Security resource types`, `Connectivity resource types`, and so on); you edit the list as a plain array and type resource-type strings like `Microsoft.Network/virtualNetworks`.
