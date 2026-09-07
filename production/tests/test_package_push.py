#!/usr/bin/env python3
"""The package cannot arrive through a redirecting URL any more.

Azure rejects the CREATE of a Linux consumption Function App whose
WEBSITE_RUN_FROM_PACKAGE points at a URL that redirects. A GitHub release
download URL always redirects (302 to objects.githubusercontent.com), so the
one-click install failed at the Function App with BadRequest 51024 and left the
storage account, the identity and the App Service Plan behind.

Measured 7 Sep 2026: the same release URL was accepted at 15:01 and rejected at
15:10, same subscription, same region, same template. Nothing in the repository
changed in between. A green E2E from yesterday proves nothing about today.

The supported shape, from the platform's own error message: create the app with
WEBSITE_RUN_FROM_PACKAGE=1 and push the package with a zip deploy. The
deploymentScript downloads PackageUri and stages it itself: it uploads the zip
as a blob in this template's own storage account and rewrites the setting to
that blob's URL with a SAS token. (`az functionapp deployment source config-zip`
was tried first and rejected: inside the container it takes the Kudu SCM path
and leaves the pointer at "1".)

These checks pin that shape. The one that is easy to lose is forceUpdateTag:
without it a redeploy PUTs the site with the full appSettings list, resetting
the setting from the blob URL back to "1", while the deploymentScript does not
re-run. The deployment reports Succeeded and the app has no package at all.
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(os.path.dirname(HERE), "azuredeploy.json")

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


with open(TEMPLATE) as handle:
    raw = handle.read()
root = json.loads(raw)
resources = root.get("resources", [])
params = root.get("parameters", {})

# Calibration: an empty search proves nothing if the file is not what we think it is.
check("Microsoft.Web/sites" in raw,
      "azuredeploy.json: no Microsoft.Web/sites in the file - these checks would all pass "
      "vacuously")

sites = [r for r in resources if r.get("type") == "Microsoft.Web/sites"]
check(len(sites) == 1,
      "azuredeploy.json: expected exactly 1 Function App, found %d" % len(sites))

# --- the setting itself -----------------------------------------------------------------
for site in sites:
    settings = {a.get("name"): a.get("value")
                for a in ((site.get("properties") or {}).get("siteConfig") or {})
                .get("appSettings", [])}
    value = settings.get("WEBSITE_RUN_FROM_PACKAGE")
    check(value == "1",
          "azuredeploy.json: WEBSITE_RUN_FROM_PACKAGE is %r, must be \"1\" - Azure rejects "
          "the create when it is a URL that redirects, and a GitHub release URL always "
          "redirects" % (value,))
    # The specific value that used to be there. Named so a revert is legible in the failure.
    check(value != "[parameters('PackageUri')]",
          "azuredeploy.json: WEBSITE_RUN_FROM_PACKAGE is back to the release URL - this is "
          "the exact shape the platform rejects with BadRequest 51024")
    # Any other setting holding an http URL that the platform would fetch at create time.
    for name, val in settings.items():
        if name == "WEBSITE_RUN_FROM_PACKAGE":
            continue
        check(not (isinstance(val, str) and val.startswith("https://github.com/")),
              "azuredeploy.json: %s points at a GitHub URL (%s) - if the platform fetches "
              "it at create time it hits the same redirect rule" % (name, val[:60]))

# --- the push -------------------------------------------------------------------------
scripts = [r for r in resources if r.get("type") == "Microsoft.Resources/deploymentScripts"]
check(len(scripts) == 1,
      "azuredeploy.json: expected exactly 1 deploymentScript, found %d - the package push "
      "lives there" % len(scripts))

for script in scripts:
    props = script.get("properties") or {}
    body = props.get("scriptContent") or ""
    check(script.get("kind") == "AzureCLI",
          "azuredeploy.json: deploymentScript kind is %r, the staging step needs AzureCLI"
          % script.get("kind"))
    check("az storage blob upload" in body and "generate-sas" in body,
          "azuredeploy.json: the deploymentScript does not push the package - with "
          "WEBSITE_RUN_FROM_PACKAGE=1 and no push the app deploys green and empty")
    check("curl" in body and "PACKAGE_URL" in body,
          "azuredeploy.json: the deploymentScript does not download PackageUri")
    # A 404 or an HTML error page is still a 200-byte file; pushing it yields 0 functions.
    check("zipfile.ZipFile" in body,
          "azuredeploy.json: the downloaded package is not verified as a readable zip (python3 does the check: unzip is absent from the newer azure-cli images) - an "
          "HTML error page would be pushed and the app would index nothing")
    # Running is not health: the count is the only signal that the package loaded.
    check("length(value)" in body and "exit 1" in body,
          "azuredeploy.json: the script does not read the function count back and fail on "
          "zero - a Running app with no functions would report success")
    check(props.get("forceUpdateTag"),
          "azuredeploy.json: the deploymentScript has no forceUpdateTag - a redeploy PUTs "
          "the site, resets WEBSITE_RUN_FROM_PACKAGE from the blob URL back to \"1\", and "
          "the script does not re-run: green deployment, empty app")
    tag = props.get("forceUpdateTag") or ""
    ref = re.match(r"^\[parameters\('([^']+)'\)\]$", tag)
    check(ref is not None,
          "azuredeploy.json: forceUpdateTag is %r - it must reference a parameter whose "
          "default changes per deployment, otherwise it never forces anything" % (tag,))
    if ref:
        decl = params.get(ref.group(1), {})
        check(decl.get("defaultValue") == "[utcNow()]",
              "azuredeploy.json: %s default is %r, must be [utcNow()] - a constant tag does "
              "not change between deployments so the push is skipped"
              % (ref.group(1), decl.get("defaultValue")))
    # Measured on a TAXII run: the pointer was written at 18:37:17, no restart
    # followed, the function was still absent when the 4 minute poll expired at
    # 18:42 -- and it appeared one minute after an explicit restart at 18:44:39.
    # So the script restarts the app itself, and the timeout has to cover the
    # restart plus a cold index on top of the settings-read window and the
    # upload attempts.
    timeout = props.get("timeout") or ""
    minutes = re.match(r"^PT(\d+)M$", timeout)
    check(minutes is not None and int(minutes.group(1)) >= 30,
          "azuredeploy.json: deploymentScript timeout is %r - the settings-read window, "
          "the six upload attempts and the 10 minute index poll need at least PT30M" % (timeout,))
    check("for i in $(seq 1 40)" in body,
          "azuredeploy.json: the index poll is shorter than a restart plus a cold index "
          "on a consumption plan - a working install would be reported Failed")
    check("functionapp restart" in body,
          "azuredeploy.json: the script writes the package pointer and waits. Writing it "
          "did not make the host reload the package on a measured TAXII run; the function "
          "appeared only after an explicit restart")
    check(body.index("staged || {") < body.index("functionapp restart"),
          "azuredeploy.json: the restart is asked for before the package is known to be "
          "staged, so it would reload the old package")
    # OnSuccess on its own is a one-hour promise: on failure the service waits for
    # retentionInterval and then deletes the container, the storage and the script
    # resource together. Measured on run 3c6f: endTime 18:42:05, expirationTime
    # 19:42:05 -- exactly the PT1H that was in the template. A customer who deploys
    # in the evening and asks in the morning would have nothing left to read.
    ri = props.get("retentionInterval")
    m_ri = re.match(r"^P(?:(\d+)D)?(?:T(\d+)H)?$", str(ri or ""))
    hours = (int(m_ri.group(1) or 0) * 24 + int(m_ri.group(2) or 0)) if m_ri else 0
    check(hours >= 26,
          "azuredeploy.json: retentionInterval is %r - the failed deployment's container "
          "and log are deleted when it expires; the documented ceiling is PT26H" % (ri,))

    check(props.get("cleanupPreference") == "OnSuccess",
          "azuredeploy.json: cleanupPreference is %r - with the default the container and "
          "its log are deleted the moment a customer's deployment fails, which is exactly "
          "the run someone asks about" % (props.get("cleanupPreference"),))
    # config-zip reported "Zip deployment failed" on TAXII while the blob had been
    # written, the pointer updated and the function indexed. Under `set -e` that
    # false negative turns a working install into a Failed deployment.
    check("the readings decide" in body,
          "azuredeploy.json: the script trusts a tool's exit code. config-zip reported "
          "failure after the package landed - the readings have to be the verdict")
    # Kudu rejects a ZipDeploy while the app is still provisioning and says only
    # "Deployment Failed" two seconds in. A single attempt after a fixed wait was
    # enough for Feeds and not for TAXII, twice.
    check("for attempt in $(seq 1 6)" in body,
          "azuredeploy.json: the push is attempted once. Kudu rejects a ZipDeploy "
          "against an app that is still provisioning, so a single attempt is a "
          "coin flip")
    # The role assignment this script depends on is not usable the moment ARM
    # reports it. The wait belongs on the first call that needs the role -- the
    # settings read -- not on a fixed sleep placed after it: a sleep there
    # protected nothing and a slow assignment surfaced as "no storage
    # connection", which is the wrong reason.
    check("for wait in $(seq 1 8)" in body,
          "azuredeploy.json: the settings read is not retried, so an assignment "
          "that is still propagating is reported as a missing storage connection")
    check(body.index("for wait in") < body.index("az storage blob upload"),
          "azuredeploy.json: the wait for the role assignment does not cover the "
          "first call that needs it")
    # Two independent readings, both required. The count alone lies: ARM reported
    # 1 function on an app whose host was 503 with the pointer left at "1".
    check("staged()" in body and "function-releases" in body,
          "azuredeploy.json: nothing checks that the pointer became a blob under "
          "function-releases - a package staged anywhere else is lost on restart")
    check(body.count("$(pointer)") == 1 and 'case "$(pointer)" in' in body,
          "azuredeploy.json: the pointer value must be read into `case` and nowhere "
          "else - echoing it writes a SAS token into the deployment log")
    # Every $VAR the body reads has to be declared. An undeclared one is an empty
    # string in bash, so `curl -L ""` returns HTTP 000 and the failure message
    # blames the package URL instead of the template. Found in TAXII, where the
    # old script only needed FA_NAME and RG_NAME.
    declared = {e.get("name") for e in (props.get("environmentVariables") or [])}
    used = set(re.findall(r"\$([A-Z][A-Z0-9_]*)", body))
    # Names the script assigns itself (BLOB, CONN, SA, SAS) are not the
    # template's job to declare.
    used -= set(re.findall(r"(?:^|[\s;&|{(])([A-Z][A-Z0-9_]*)=", body))
    used -= {"i", "n", "code"}  # locals, not environment
    undeclared = sorted(used - declared)
    check(not undeclared,
          "azuredeploy.json: the deploymentScript reads %s but the template does not "
          "declare them - bash expands an undeclared variable to the empty string and the "
          "script fails on a message that points at the wrong thing" % undeclared)

    # The script reads and writes app settings through ARM: the role has to be there first.
    deps = " ".join(script.get("dependsOn") or [])
    check("WebsiteContributorRoleId" in deps or "Website" in deps,
          "azuredeploy.json: the deploymentScript does not wait for the Website Contributor "
          "role assignment - the script cannot read the storage connection or set the pointer without it")

# --- the parameter is still wired -------------------------------------------------------
check("PackageUri" in params,
      "azuredeploy.json: PackageUri parameter is gone but the script still needs a source")
check(raw.count("parameters('PackageUri')") >= 1,
      "azuredeploy.json: PackageUri is declared and never referenced - the package would "
      "come from nowhere")

print("\n".join("  - %s" % f for f in failures))
if failures:
    print("%d problem(s) in %d checks." % (len(failures), checks))
    sys.exit(1)
print("package push: created with \"1\", pushed by zip deploy, re-pushed on redeploy "
      "(%d checks)" % checks)
