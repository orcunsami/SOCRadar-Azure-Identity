#!/usr/bin/env python3
"""Break the code on purpose and prove the tests notice.

Each entry below breaks one invariant, runs the test that should catch it, and
restores the file. A mutation that survives is BLIND and the run exits non-zero.

Bytecode is disabled for the child runs: a same-size mutation applied and
reverted inside one second leaves a .pyc that still looks current, and the next
run would execute the mutated bytecode.

    python3 tests/mutate.py
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
 ('onboarding guard always runs', 'azuredeploy.json',
  '"condition": "[parameters(\'EnableCreateIncident\')]",', '',
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
]
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
