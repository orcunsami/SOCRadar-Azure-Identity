#!/usr/bin/env python3
"""Break the code on purpose and prove the tests notice.

Each entry below breaks one invariant, runs the test that should catch it, and
restores the file. A mutation that survives is BLIND and the run exits non-zero.

Bytecode is disabled for the child runs: a same-size mutation applied and
reverted inside one second leaves a .pyc that still looks current, and the next
run would execute the mutated bytecode.

    python3 tests/mutate.py

The code tests import the Function App, so run it with an interpreter that has
FunctionApp/requirements.txt installed.
"""

import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MUTATIONS = [
 ('pointer reading removed', 'azuredeploy.json',
  'staged() { [ \\"$(shape)\\" = blob ]; }; ', '',
  'tests/test_package_push.py'),
 ('pointer echoed with its SAS', 'azuredeploy.json',
  'staged() { [ \\"$(shape)\\" = blob ]; }; ', 'staged() { echo \\"$(pointer)\\"; [ \\"$(shape)\\" = blob ]; }; ',
  'tests/test_package_push.py'),
 ('settings read not retried', 'azuredeploy.json',
  'for wait in $(seq 1 8); ', 'for wait in $(seq 1 1); ',
  'tests/test_package_push.py'),
 ('single push attempt', 'azuredeploy.json',
  'for attempt in $(seq 1 6); ', 'for attempt in $(seq 1 1); ',
  'tests/test_package_push.py'),
 ('index poll cut to one minute', 'azuredeploy.json',
  'for i in $(seq 1 40); ', 'for i in $(seq 1 4); ',
  'tests/test_package_push.py'),
 ('no restart after staging', 'azuredeploy.json',
  'az functionapp restart ', 'true restart ',
  'tests/test_package_push.py'),
 ('container log deleted on failure', 'azuredeploy.json',
  '"cleanupPreference": "OnSuccess"', '"cleanupPreference": "Always"',
  'tests/test_package_push.py'),
 ("failed run's evidence expires in an hour", 'azuredeploy.json',
  '"retentionInterval": "PT26H"', '"retentionInterval": "PT1H"',
  'tests/test_package_push.py'),

 # EXP-AZURE-0198: a wrong workspace must stop the deployment before anything
 # is created. Measured live in rg-id-base-27c9 on 7 Sep 2026: four orphans.
 ('guard evaluated in the parent', 'azuredeploy.json',
  '"scope": "inner"', '"scope": "outer"',
  'tests/test_workspace_guard.py'),
 ('guard resolves nothing', 'azuredeploy.json',
  "[reference(parameters('WorkspaceResourceId'), '2023-09-01', 'Full').properties.customerId]",
  "[parameters('WorkspaceResourceId')]",
  'tests/test_workspace_guard.py'),
 ('onboarding guard reads the workspace instead', 'azuredeploy.json',
  "/providers/Microsoft.SecurityInsights/onboardingStates/default", "",
  'tests/test_workspace_guard.py'),
 ('first resource stops waiting for the guard', 'azuredeploy.json',
  '''            "dependsOn": [
                "[resourceId('Microsoft.Resources/deployments', 'precheck-workspace-exists')]",
                "[resourceId('Microsoft.Resources/deployments', 'precheck-sentinel-onboarded')]"
            ]''',
  '''            "dependsOn": []''',
  'tests/test_workspace_guard.py'),
 ('workspace id blind to the workspace resource group', 'azuredeploy.json',
  "[resourceId(subscription().subscriptionId, if(empty(parameters('WorkspaceResourceGroup')), resourceGroup().name, parameters('WorkspaceResourceGroup')), 'Microsoft.OperationalInsights/workspaces', parameters('WorkspaceName'))]",
  "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('WorkspaceName'))]",
  'tests/test_workspace_guard.py'),
 
 # Audit 0080 (identity.md): the code paths that lose data. The first two cover test_fetch_failed.py,
 # which had no mutation before; the rest cover test_silent_loss.py.
 ('unfinished SOCRadar read forgotten by the caller', 'FunctionApp/function_app.py',
  'fetch_failed = any(e.get("_fetch_failed") for e in employees)', 'fetch_failed = False',
  'tests/test_fetch_failed.py'),
 ('failed domain not marked by the source', 'FunctionApp/sources/identity.py',
  'all_records[-1]["_fetch_failed"] = True', 'pass',
  'tests/test_fetch_failed.py'),
 ('LAW write result ignored', 'FunctionApp/actions/law_writer.py',
  '        if not _post(workspace_id, workspace_key, log_type, batch):\n            failed += 1\n',
  '        _post(workspace_id, workspace_key, log_type, batch)\n',
  'tests/test_silent_loss.py'),
 ('Graph 403 read as user not found', 'FunctionApp/actions/entra_id.py',
  'raise GraphLookupError(f"HTTP {resp.status_code}")', 'return None',
  'tests/test_silent_loss.py'),
 ('Graph throttling not retried', 'FunctionApp/actions/entra_id.py',
  'and attempt < 2:', 'and attempt < 0:',
  'tests/test_silent_loss.py'),
 ('checkpoint saved although a record may be lost', 'FunctionApp/function_app.py',
  'if new_checkpoint and not hold:', 'if new_checkpoint:',
  'tests/test_silent_loss.py'),
 ('missing Graph token not counted', 'FunctionApp/function_app.py',
  '    if graph_headers is None:\n        logger.error("[ENTRA] No Graph token',
  '    if False:\n        logger.error("[ENTRA] No Graph token',
  'tests/test_silent_loss.py'),
 ('Graph lookup error does not hold the checkpoint', 'FunctionApp/function_app.py',
  '                hold = True\n                emp["entra_status"] = "lookup_error"',
  '                emp["entra_status"] = "lookup_error"',
  'tests/test_silent_loss.py'),
 ('per-record exception does not hold the checkpoint', 'FunctionApp/function_app.py',
  '            errors += 1\n            hold = True\n\n    # Write records to LAW',
  '            errors += 1\n\n    # Write records to LAW',
  'tests/test_silent_loss.py'),
 ('incident failure not counted', 'FunctionApp/function_app.py',
  'if not sent.create_incident(', 'if False and not sent.create_incident(',
  'tests/test_silent_loss.py'),
 ('every domain starts from one shared date', 'FunctionApp/sources/identity.py',
  'start = prev.get("date") or default_start', 'start = default_start',
  'tests/test_silent_loss.py'),
 ('seen ids not remembered', 'FunctionApp/sources/identity.py',
  'if short and short in seen_old:', 'if False:',
  'tests/test_silent_loss.py'),
 ('empty window counted as a record', 'FunctionApp/sources/identity.py',
  '{"_checkpoint_update": update, "_empty_marker": True}', '{"_checkpoint_update": update}',
  'tests/test_silent_loss.py'),
 ('already-a-member wording too narrow', 'FunctionApp/actions/entra_id.py',
  '"already exist" in resp.text.lower()', '"already exists" in resp.text.lower()',
  'tests/test_silent_loss.py'),
 ('HTTP 402 not explained as ambiguous', 'FunctionApp/sources/identity.py',
  'if resp.status_code == 402:', 'if resp.status_code == 0:',
  'tests/test_fetch_failed.py'),
 ('email not encoded in the lookup URL', 'FunctionApp/actions/entra_id.py',
  "quote(email, safe='@')", 'email',
  'tests/test_silent_loss.py'),
 ('incident labels lose their type', 'FunctionApp/actions/sentinel.py',
  '{"labelName": "SOCRadar", "labelType": "User"},', '{"labelName": "SOCRadar"},',
  'tests/test_silent_loss.py'),
 ('package URL failure back on stdout', 'azuredeploy.json',
  r'''echo \"package URL returned HTTP $code\" >&2; exit 1''',
  r'''echo \"package URL returned HTTP $code\"; exit 1''',
  'tests/test_script_messages.py'),
 ('index timeout failure back on stdout', 'azuredeploy.json',
  r'''no function was indexed in 10 minutes' >&2; exit 1''',
  r'''no function was indexed in 10 minutes'; exit 1''',
  'tests/test_script_messages.py'),

 # IncidentMode / AlertBacked: the rule must be on only in AlertBacked, in every mode it must
 # exist (a switch back must be able to turn it off), and it must never read a credential column.
 ('rule always on', 'azuredeploy.json',
  '"enabled": "[parameters(\'RuleEnabled\')]"', '"enabled": true',
  'tests/test_incident_mode.py'),
 ('labeling automation rule always on', 'azuredeploy.json',
  '"isEnabled": "[parameters(\'RuleEnabled\')]"', '"isEnabled": true',
  'tests/test_incident_mode.py'),
 ('rule on in Direct', 'azuredeploy.json',
  '"value": "[equals(variables(\'effectiveIncidentMode\'), \'AlertBacked\')]"',
  '"value": "[equals(variables(\'effectiveIncidentMode\'), \'Direct\')]"',
  'tests/test_incident_mode.py'),
 ('rules only exist in AlertBacked', 'azuredeploy.json',
  '"name": "socradar-identity-alert-rules",',
  '"name": "socradar-identity-alert-rules",\n            "condition": "[equals(parameters(\'IncidentMode\'), \'AlertBacked\')]",',
  'tests/test_incident_mode.py'),
 ('legacy flag no longer means Direct', 'azuredeploy.json',
  "[if(and(equals(parameters('IncidentMode'), 'None'), parameters('EnableCreateIncident')), 'Direct', parameters('IncidentMode'))]",
  "[parameters('IncidentMode')]",
  'tests/test_incident_mode.py'),
 ('AlertBacked still PUTs', 'azuredeploy.json',
  "[string(equals(variables('effectiveIncidentMode'), 'Direct'))]",
  "[string(not(equals(variables('effectiveIncidentMode'), 'None')))]",
  'tests/test_incident_mode.py'),
 ('rule reads a credential column', 'azuredeploy.json',
  '| project TimeGenerated, DedupKey,', '| project TimeGenerated, password_masked_s, DedupKey,',
  'tests/test_incident_mode.py'),
 ('rules ignore WorkspaceResourceGroup', 'azuredeploy.json',
  '"resourceGroup": "[variables(\'workspaceRg\')]"', '"resourceGroup": "[resourceGroup().name]"',
  'tests/test_incident_mode.py'),
 ('rule alerts every row twice', 'azuredeploy.json',
  '| join kind=leftanti Alerted on $left.DedupKey == $right.AlertedKey\\n', '',
  'tests/test_incident_mode.py'),
 ('no hold on fresh rows', 'azuredeploy.json',
  '| where TimeGenerated < ago(12m)', '| where TimeGenerated < ago(1m)',
  'tests/test_incident_mode.py'),
 ('rule runs every 10 minutes again', 'azuredeploy.json',
  '"queryFrequency": "PT1H"', '"queryFrequency": "PT10M"',
  'tests/test_incident_mode.py'),
 ('rule window one day', 'azuredeploy.json',
  '"queryPeriod": "P7D"', '"queryPeriod": "P1D"',
  'tests/test_incident_mode.py'),
 ('query window one day', 'azuredeploy.json',
  '| where TimeGenerated > ago(7d)', '| where TimeGenerated > ago(1d)',
  'tests/test_incident_mode.py'),
 ('label IDENTITY renamed', 'azuredeploy.json',
  '"labelName": "IDENTITY"', '"labelName": "Identity"',
  'tests/test_incident_mode.py'),
 ('more than 150 alerts a run', 'azuredeploy.json',
  '| take 149', '| take 500',
  'tests/test_incident_mode.py'),
 ('Sentinel check conditional again', 'azuredeploy.json',
  '"name": "precheck-sentinel-onboarded",',
  '"name": "precheck-sentinel-onboarded",\n            "condition": "[parameters(\'EnableCreateIncident\')]",',
  'tests/test_workspace_guard.py'),
]
# A test that fails on the untouched tree "catches" every mutation for free (a missing azure
# package alone made 17 of them look caught). Run every test once, unmodified, first.
red = []
for test in sorted({m[4] for m in MUTATIONS}):
    r = subprocess.run([sys.executable, test], cwd=REPO, capture_output=True, text=True, timeout=120,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    if r.returncode != 0:
        red.append(test)
if red:
    print("BASELINE RED: %s fail before any mutation, so no mutation result can be trusted" % ", ".join(red))
    sys.exit(2)
blind = []
for name, path, old, new, test in MUTATIONS:
    full = os.path.join(REPO, path)
    orig = open(full, encoding="utf-8").read()
    if old not in orig:
        print("SKIP  %-32s anchor not found in %s" % (name, path)); blind.append(name); continue
    try:
        open(full, "w", encoding="utf-8").write(orig.replace(old, new, 1))
        try:
            r = subprocess.run([sys.executable, test], cwd=REPO, capture_output=True, text=True, timeout=60,
                               env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
            rc = r.returncode
        except subprocess.TimeoutExpired:
            rc = 124
    finally:
        open(full, "w", encoding="utf-8").write(orig)
    if rc == 0:
        print("BLIND %-32s %s still passed" % (name, test)); blind.append(name)
    else:
        print("caught %-31s %s" % (name, test))
print("\nblind:", len(blind), "of", len(MUTATIONS))
sys.exit(1 if blind else 0)
