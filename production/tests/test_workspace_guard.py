#!/usr/bin/env python3
"""A wrong workspace must stop the deployment before anything is created.

Measured on 7 Sep 2026 in resource group rg-id-base-27c9, before this guard
existed: deploying with WorkspaceName set to a workspace that does not exist
returned Failed with ResourceNotFound and left four resources behind - the
storage account, the App Service Plan, Application Insights and the
user-assigned identity. Nothing in the template waited for the workspace. The
first thing that touched it was the Function App's app settings, which read the
workspace's customerId and its shared key, and by then the rest was built.

Depending on the workspace resource is not a fix here and would not have been
one anywhere: ARM counts a resource whose condition is false as a satisfied
dependency (EXP-AZURE-0198). This template does not even declare a workspace -
it requires an existing one - so the guard is a nested deployment that resolves
the workspace and that every resource waits on.

Two guards, because there are two ways to be pointed at the wrong place:

  precheck-workspace-exists     unconditional; the workspace must resolve
  precheck-sentinel-onboarded   unconditional since IncidentMode; the analytics
                                rules deploy in every mode (a conditional rules
                                module would leave them on after a switch)

The second one exists because the rules and the Direct mode write to
Microsoft.SecurityInsights. Without Microsoft Sentinel on the workspace those
fail, and Direct fails at runtime hours after a green deployment
(EXP-AZURE-0200). This template never onboards Microsoft Sentinel itself.

The third thing checked here is the workspace resource id. resourceId() with
only a type and a name always resolves inside the deployment resource group,
so the WorkspaceResourceGroup parameter - documented as "for cross-RG
deployments" - was ignored and cross-RG never worked (the same class as the
MSSP defect found on 7 Sep 2026).
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(os.path.dirname(HERE), "azuredeploy.json")

GUARD = "precheck-workspace-exists"
ONBOARD = "precheck-sentinel-onboarded"

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


raw = open(TEMPLATE, encoding="utf-8").read()
doc = json.loads(raw)
resources = doc["resources"]
by_name = {r.get("name"): r for r in resources}

# --- the guards exist and are shaped so they can actually fail -------------

for name, condition in ((GUARD, None), (ONBOARD, None)):
    res = by_name.get(name)
    check(res is not None,
          "azuredeploy.json: %s is gone - a wrong workspace would half-install again" % name)
    if res is None:
        continue
    check(res.get("type") == "Microsoft.Resources/deployments",
          "azuredeploy.json: %s must be a nested deployment" % name)
    scope = res.get("properties", {}).get("expressionEvaluationOptions", {}).get("scope")
    check(scope == "inner",
          "azuredeploy.json: %s has scope %r - with outer the expression is evaluated in "
          "the parent and the guard passes for a workspace that does not exist" % (name, scope))
    check(res.get("condition") == condition,
          "azuredeploy.json: %s condition is %r, expected %r"
          % (name, res.get("condition"), condition))
    outputs = res.get("properties", {}).get("template", {}).get("outputs", {})
    check(len(outputs) >= 1,
          "azuredeploy.json: %s has no output - a nested deployment that resolves nothing "
          "always succeeds" % name)
    values = " ".join(str(o.get("value", "")) for o in outputs.values())
    check("reference(" in values,
          "azuredeploy.json: %s does not call reference() - resourceId() is string "
          "arithmetic and succeeds for a resource that was never created" % name)
    inner = res.get("properties", {}).get("template", {}).get("resources", [])
    check(inner == [],
          "azuredeploy.json: %s deploys resources of its own; it is a lookup, not a "
          "deployment" % name)

# the onboarding guard must read the onboarding state, not the workspace again
onboard_values = " ".join(
    str(o.get("value", "")) for o in
    by_name.get(ONBOARD, {}).get("properties", {}).get("template", {}).get("outputs", {}).values())
check("onboardingStates/default" in onboard_values,
      "azuredeploy.json: %s does not read onboardingStates/default, so a workspace "
      "without Microsoft Sentinel still passes" % ONBOARD)

# --- everything else waits on both ----------------------------------------

for res in resources:
    name = res.get("name")
    if name in (GUARD, ONBOARD):
        continue
    deps = json.dumps(res.get("dependsOn", []))
    for guard in (GUARD, ONBOARD):
        check(guard in deps,
              "azuredeploy.json: %r does not wait for %s, so it is created before the "
              "workspace is known to exist" % (str(name)[:48], guard))

check(len(resources) >= 3,
      "azuredeploy.json: fewer than three resources - has the template been truncated?")

# --- the workspace resource id honours WorkspaceResourceGroup -------------

wsid = doc["variables"].get("workspaceResourceId", "")
check("WorkspaceResourceGroup" in wsid,
      "azuredeploy.json: workspaceResourceId ignores WorkspaceResourceGroup, so a cross-RG "
      "deployment looks for the workspace in the deployment resource group")
check("subscription().subscriptionId" in wsid,
      "azuredeploy.json: workspaceResourceId omits the subscription argument; resourceId() "
      "needs it before a resource group can be given")
check("parameters('WorkspaceName')" in wsid,
      "azuredeploy.json: workspaceResourceId no longer names WorkspaceName")

# the guard must be handed that same id, not build its own
guard_params = json.dumps(by_name.get(GUARD, {}).get("properties", {}).get("parameters", {}))
check("WorkspaceResourceGroup" in guard_params or "workspaceResourceId" in guard_params,
      "azuredeploy.json: %s builds its own workspace id and can drift from the one the "
      "app settings use" % GUARD)

if failures:
    print()
    for f in failures:
        print("FAIL  " + f)
    print("\n%d of %d checks failed." % (len(failures), checks))
    sys.exit(1)

print("\nworkspace guard: both prechecks resolve the workspace before anything is created "
      "(%d checks)" % checks)
