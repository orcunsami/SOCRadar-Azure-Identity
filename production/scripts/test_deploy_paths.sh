#!/usr/bin/env bash
# Regression test for EXP-AZURE-0198 and EXP-AZURE-0200, ported to Identity.
#
# Measured on 7 Sep 2026 in rg-id-base-27c9, before the guard existed: a wrong
# WorkspaceName returned Failed with ResourceNotFound and left FOUR resources
# behind -- the storage account, the App Service Plan, Application Insights and
# the user-assigned identity. Nothing in the template waited for the workspace;
# the first thing that touched it was the Function App's app settings, which
# read the workspace's customerId and its shared key.
#
# This template never creates a workspace and never onboards Microsoft
# Sentinel, so both are somebody else's job and both have to be checked:
#
#   precheck-workspace-exists     unconditional
#   precheck-sentinel-onboarded   only when EnableCreateIncident is on, because
#                                 the Function App writes to
#                                 Microsoft.SecurityInsights/incidents and that
#                                 fails at runtime, hours after a green deploy
#
# Six paths:
#   A  missing workspace                       -> fails, resource group EMPTY
#   B  existing workspace, incidents off       -> succeeds, onboarding guard SKIPPED
#   C  existing onboarded workspace, incidents on -> both guards SUCCEED
#   D  workspace without Microsoft Sentinel, incidents on -> rejected, nothing created
#   E  cross-RG onto an onboarded workspace    -> succeeds (workspaceResourceId fix)
#   F  redeploy of B's resource group          -> the guard does not block it
#
# C and E matter most. B skips the onboarding guard, so a wrong api-version or
# field name inside it would leave the cheap paths green and fail only at a
# customer -- that is how reference(...).name once shipped in Incidents. And E
# is the path that never worked at all: resourceId() without a resource group
# always resolves in the deployment RG, so WorkspaceResourceGroup, documented
# as "for cross-RG deployments", was ignored.
#
# No SOCRadar or Entra ID credentials are needed. Placeholders are passed so no
# real secret enters a test run.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE="$ROOT/azuredeploy.json"

# No hardcoded subscription default, and never passed per command: `az
# --subscription <id> group create` is rejected by this CLI (the flag only
# parses AFTER the subcommand) and a shell variable holding the prefix behaves
# differently in bash and zsh. Both were tried in the MSSP harness and both
# produced a run where every assertion read <unreadable>. EXP-AZURE-0207.
SUBSCRIPTION="$(az account show --query id -o tsv 2>/dev/null || true)"
if [ -z "$SUBSCRIPTION" ]; then
    echo "ERROR: not logged in. Run 'az login'." >&2
    exit 2
fi
if [ -n "${TEST_SUBSCRIPTION:-}" ] && [ "$TEST_SUBSCRIPTION" != "$SUBSCRIPTION" ]; then
    echo "ERROR: TEST_SUBSCRIPTION is $TEST_SUBSCRIPTION but the active context is" >&2
    echo "       $SUBSCRIPTION. Run: az account set --subscription $TEST_SUBSCRIPTION" >&2
    exit 2
fi
LOCATION="${TEST_LOCATION:-westeurope}"
KEEP="${KEEP_RESOURCES:-false}"

# TEST_PACKAGE_URI substitutes another package for the template's PackageUri
# default, e.g. a build staged in a blob before it is published. Leave it empty
# to run the paths exactly as a customer does, against the published release.
# (Until 10 Sep 2026 the default was a 404: the product had no release at all.)
PACKAGE_URI="${TEST_PACKAGE_URI:-}"

SFX=$(python3 -c "import uuid;print(uuid.uuid4().hex[:4])")
RG_APP="rg-id-paths-$SFX"       # B, F: app and workspace together
RG_BARE="rg-id-paths-bare-$SFX" # D: workspace with no Microsoft Sentinel
RG_D="rg-id-paths-d-$SFX"       # D: the deployment that must be rejected
RG_C="rg-id-paths-c-$SFX"       # C: incidents on, same RG as its workspace
RG_X="rg-id-paths-x-$SFX"       # E: cross-RG deployment
WS="ws-id-paths-$SFX"
WS_BARE="ws-id-bare-$SFX"
WS_ONB="ws-id-onb-$SFX"      # C creates it in RG_C and E reaches it cross-RG
MISSING="ws-does-not-exist-$SFX"

fails=0
row() {  # row <name> <PASS|FAIL> <detail>
    printf '%-42s %-5s %s\n' "$1" "$2" "$3"
    [ "$2" = PASS ] || fails=$((fails + 1))
}

cleanup() {
    local rgs="$RG_APP $RG_BARE $RG_D $RG_C $RG_X"
    if [ "$KEEP" = true ]; then
        echo "KEEP_RESOURCES=true, leaving $rgs in place"
        return
    fi
    for rg in $rgs; do
        az group delete -n "$rg" --yes --no-wait -o none 2>/dev/null
    done
    echo "cleanup: delete queued for $rgs"
}
trap cleanup EXIT

deploy() {  # deploy <rg> <name> <extra params...>
    local rg="$1" name="$2"; shift 2
    az deployment group create -g "$rg" -n "$name" --template-file "$TEMPLATE" \
        --parameters SocradarIdentityApiKey="placeholder-not-a-real-key" \
                     MonitoredDomains="example.com" \
                     EntraIdTenantId="00000000-0000-0000-0000-000000000000" \
                     EntraIdClientId="00000000-0000-0000-0000-000000000000" \
                     EntraIdClientSecret="placeholder-not-a-real-secret" \
                     WorkspaceLocation="$LOCATION" \
                     ${PACKAGE_URI:+PackageUri="$PACKAGE_URI"} "$@" \
        -o none 2>/dev/null
}

# Why a deployment failed, read from Azure rather than guessed. Run 1 of this
# harness printed "the guard blocks a workspace that exists" for four paths
# that had failed on the package URL, because the message was written as a
# hypothesis and the hypothesis was wrong. A test that names the wrong cause
# costs more than one that says nothing.
blame_detail() {  # blame_detail <rg> <deployment>
    az deployment operation group list -g "$1" -n "$2" \
        --query "[?properties.provisioningState=='Failed'].[properties.targetResource.resourceName, properties.statusMessage.error.code] | [0]" \
        -o tsv 2>/dev/null | tr '\t' ' '
}

state() {  # state <rg> <deployment>
    az deployment group show -g "$1" -n "$2" --query properties.provisioningState -o tsv 2>/dev/null
}

count() {  # count <rg>
    az resource list -g "$1" --query "length(@)" -o tsv 2>/dev/null
}

onboard() {  # onboard <rg> <workspace>
    az rest --method PUT \
        --url "https://management.azure.com/subscriptions/$SUBSCRIPTION/resourceGroups/$1/providers/Microsoft.OperationalInsights/workspaces/$2/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2023-02-01" \
        --body '{"properties":{}}' -o none 2>/dev/null
}

echo "[0/6] Target subscription: $SUBSCRIPTION"
for rg in "$RG_APP" "$RG_BARE" "$RG_D" "$RG_C" "$RG_X"; do
    az group create -n "$rg" -l "$LOCATION" -o none
done

# ---------------------------------------------------------------- A ---------
echo "[1/6] Path A: a workspace that does not exist ..."
deploy "$RG_APP" path-a WorkspaceName="$MISSING"
st=$(state "$RG_APP" path-a)
[ "$st" = Failed ] \
    && row "A deployment fails" PASS "$st" \
    || row "A deployment fails" FAIL "expected Failed, got '${st:-<unreadable>}'"

n=$(count "$RG_APP")
[ "$n" = 0 ] \
    && row "A leaves nothing behind" PASS "0 resources" \
    || row "A leaves nothing behind" FAIL "expected 0 resources, found '${n:-<unreadable>}' - before the guard this was 4"

blame=$(az deployment operation group list -g "$RG_APP" -n path-a \
    --query "[?properties.provisioningState=='Failed'].properties.targetResource.resourceName" -o tsv 2>/dev/null | head -1)
[ "$blame" = precheck-workspace-exists ] \
    && row "A blames the precheck" PASS "$blame" \
    || row "A blames the precheck" FAIL "the precheck was not the failing step: '${blame:-<unreadable>}'"

# ---------------------------------------------------------------- B ---------
echo "[2/6] Path B: an existing workspace, incident creation off ..."
az monitor log-analytics workspace create -g "$RG_APP" -n "$WS" -l "$LOCATION" -o none 2>/dev/null
deploy "$RG_APP" path-b WorkspaceName="$WS" EnableCreateIncident=false
st=$(state "$RG_APP" path-b)
[ "$st" = Succeeded ] \
    && row "B succeeds against a real workspace" PASS "$st" \
    || row "B succeeds against a real workspace" FAIL "expected Succeeded, got '${st:-<unreadable>}', failing step: $(blame_detail "$RG_APP" path-b)"

gst=$(state "$RG_APP" precheck-workspace-exists)
[ "$gst" = Succeeded ] \
    && row "B workspace guard succeeds" PASS "$gst" \
    || row "B workspace guard succeeds" FAIL "expected Succeeded, got '${gst:-<unreadable>}' - reference() may name a field or api-version that does not exist"

cid=$(az deployment group show -g "$RG_APP" -n precheck-workspace-exists \
    --query properties.outputs.workspaceId.value -o tsv 2>/dev/null)
case "$cid" in
    ????????-????-????-????-????????????) row "B guard resolves customerId" PASS "looks like a guid" ;;
    *) row "B guard resolves customerId" FAIL "output was '${cid:-<empty>}'" ;;
esac

ost=$(state "$RG_APP" precheck-sentinel-onboarded)
[ -z "$ost" ] \
    && row "B skips the onboarding guard" PASS "condition false" \
    || row "B skips the onboarding guard" FAIL "it ran anyway: '$ost' - incident creation is off here"

# ---------------------------------------------------------------- C ---------
echo "[3/6] Path C: an onboarded workspace, incident creation on ..."
az monitor log-analytics workspace create -g "$RG_C" -n "$WS_ONB" -l "$LOCATION" -o none 2>/dev/null
onboard "$RG_C" "$WS_ONB"
fixture=$(az rest --method GET \
    --url "https://management.azure.com/subscriptions/$SUBSCRIPTION/resourceGroups/$RG_C/providers/Microsoft.OperationalInsights/workspaces/$WS_ONB/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2023-02-01" \
    --query name -o tsv 2>/dev/null)
[ "$fixture" = default ] \
    && row "C fixture: workspace onboarded" PASS "onboardingStates/default" \
    || row "C fixture: workspace onboarded" FAIL "the fixture itself did not onboard: '${fixture:-<unreadable>}'"

deploy "$RG_C" path-c WorkspaceName="$WS_ONB" EnableCreateIncident=true
st=$(state "$RG_C" path-c)
[ "$st" = Succeeded ] \
    && row "C succeeds with incidents on" PASS "$st" \
    || row "C succeeds with incidents on" FAIL "expected Succeeded, got '${st:-<unreadable>}', failing step: $(blame_detail "$RG_C" path-c)"

ost=$(state "$RG_C" precheck-sentinel-onboarded)
[ "$ost" = Succeeded ] \
    && row "C onboarding guard succeeds" PASS "$ost" \
    || row "C onboarding guard succeeds" FAIL "expected Succeeded, got '${ost:-<unreadable>}' - this branch is skipped by every other path"

oid=$(az deployment group show -g "$RG_C" -n precheck-sentinel-onboarded \
    --query properties.outputs.onboardingStateId.value -o tsv 2>/dev/null)
case "$oid" in
    */providers/Microsoft.SecurityInsights/onboardingStates/default) row "C guard reads the onboarding state" PASS "resolved the resource id" ;;
    *) row "C guard reads the onboarding state" FAIL "output was '${oid:-<empty>}'" ;;
esac

# ---------------------------------------------------------------- D ---------
echo "[4/6] Path D: a workspace with no Microsoft Sentinel, incidents on ..."
az monitor log-analytics workspace create -g "$RG_BARE" -n "$WS_BARE" -l "$LOCATION" -o none 2>/dev/null
deploy "$RG_D" path-d WorkspaceName="$WS_BARE" WorkspaceResourceGroup="$RG_BARE" EnableCreateIncident=true
st=$(state "$RG_D" path-d)
[ "$st" = Failed ] \
    && row "D rejects a workspace without Sentinel" PASS "$st" \
    || row "D rejects a workspace without Sentinel" FAIL "expected Failed, got '${st:-<unreadable>}' - a green deploy here means incidents fail at runtime"

n=$(count "$RG_D")
[ "$n" = 0 ] \
    && row "D leaves nothing behind" PASS "0 resources" \
    || row "D leaves nothing behind" FAIL "expected 0, found '${n:-<unreadable>}'"

# ---------------------------------------------------------------- E ---------
echo "[5/6] Path E: cross-RG onto the workspace C onboarded ..."
deploy "$RG_X" path-e WorkspaceName="$WS_ONB" WorkspaceResourceGroup="$RG_C" EnableCreateIncident=true
st=$(state "$RG_X" path-e)
[ "$st" = Succeeded ] \
    && row "E cross-RG succeeds" PASS "$st" \
    || row "E cross-RG succeeds" FAIL "expected Succeeded, got '${st:-<unreadable>}', failing step: $(blame_detail "$RG_X" path-e)"

gst=$(state "$RG_X" precheck-workspace-exists)
[ "$gst" = Succeeded ] \
    && row "E guard resolves the external workspace" PASS "$gst" \
    || row "E guard resolves the external workspace" FAIL "expected Succeeded, got '${gst:-<unreadable>}'"

wsid=$(az functionapp config appsettings list -g "$RG_X" \
    -n "$(az functionapp list -g "$RG_X" --query "[0].name" -o tsv 2>/dev/null)" \
    --query "[?name=='WORKSPACE_RESOURCE_GROUP'].value | [0]" -o tsv 2>/dev/null)
[ "$wsid" = "$RG_C" ] \
    && row "E app setting names the workspace RG" PASS "$wsid" \
    || row "E app setting names the workspace RG" FAIL "expected $RG_C, got '${wsid:-<unreadable>}'"

# ---------------------------------------------------------------- F ---------
echo "[6/6] Path F: redeploying B's resource group with the guard active ..."
deploy "$RG_APP" path-f WorkspaceName="$WS" EnableCreateIncident=false
st=$(state "$RG_APP" path-f)
[ "$st" = Succeeded ] \
    && row "F redeploy succeeds" PASS "$st" \
    || row "F redeploy succeeds" FAIL "expected Succeeded, got '${st:-<unreadable>}', failing step: $(blame_detail "$RG_APP" path-f)"

echo
if [ "$fails" -eq 0 ]; then
    echo "All six deployment paths behaved as asserted."
else
    echo "$fails assertion(s) failed."
fi
exit 0
