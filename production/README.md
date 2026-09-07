# SOCRadar Identity Intelligence Integration for Microsoft Sentinel

Pulls leaked employee credentials from SOCRadar Identity Intelligence API and takes automated remediation actions in Microsoft Entra ID.

## Deployment

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Forcunsami%2FSOCRadar-Azure-Identity%2Fmaster%2Fproduction%2Fazuredeploy.json)

### Required Parameters

| Parameter | Description |
|-----------|-------------|
| SocradarIdentityApiKey | SOCRadar Identity Intelligence API key (pay-per-use, separate from Platform key) |
| MonitoredDomains | Comma-separated domains to monitor (e.g., `contoso.com,fabrikam.com`) |
| WorkspaceName | Microsoft Sentinel Log Analytics Workspace name. It must already exist -- see below |
| EntraIdTenantId | Microsoft Entra ID tenant ID |
| EntraIdClientId | App Registration client ID |
| EntraIdClientSecret | App Registration client secret |

The workspace ID and its shared key used to be asked for here. They are not
parameters: the template reads both from the workspace you name.

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| WorkspaceResourceGroup | (deployment RG) | Set it when the workspace lives in another resource group |
| EnableCreateIncident | false | Create Microsoft Sentinel incidents for compromised accounts. Requires Microsoft Sentinel on the workspace |

### The workspace has to exist before you deploy

This template does not create a Log Analytics workspace and does not onboard
Microsoft Sentinel. A wrong `WorkspaceName` fails the deployment in its first
step, `precheck-workspace-exists`, and creates nothing. It used to create the
storage account, the App Service Plan, Application Insights and the identity
before failing.

With `EnableCreateIncident` on, a second step checks that Microsoft Sentinel is
actually onboarded on that workspace. Without that check the deployment went
green and incident creation failed later, at runtime.

### A failed Failure-Anomalies deployment is Azure's, not ours

After a successful install the resource group's deployment history may show a
failed `Failure-Anomalies-Alert-Rule-Deployment`. Azure creates that smart
detection rule by itself when Application Insights is created, and it fails
with `MissingSubscriptionRegistration` when `Microsoft.AlertsManagement` is not
registered in the subscription. The integration is unaffected. To make it stop:

```bash
az provider register --namespace Microsoft.AlertsManagement
```

## Post-Deployment

The Function App runs every 6 hours (configurable via `POLLING_SCHEDULE`). First run triggers automatically on deployment.

### LAW Tables

| Table | Description |
|-------|-------------|
| SOCRadar_Identity_CL | Leaked credential records with Entra ID status |
| SOCRadar_Identity_Audit_CL | Import run audit logs |

### Entra ID Permissions

The App Registration needs these Microsoft Graph API permissions (Application type):

| Permission | Purpose |
|------------|---------|
| User.Read.All | Look up users by email |
| User.RevokeSessions.All | Revoke active sessions |
| GroupMember.ReadWrite.All | Add to security group |
| User.ReadWrite.All | Disable account, force password change |
| IdentityRiskyUser.ReadWrite.All | Confirm compromised (requires P1/P2) |

### Workbook

Import `Workbooks/SOCRadar-Identity-Workbook.json` into Microsoft Sentinel for dashboard visualization.

## How the code gets there

The template creates the Function App empty (`WEBSITE_RUN_FROM_PACKAGE=1`) and a deployment
script downloads `PackageUri`, verifies it is a readable zip, uploads it to the storage account
this template creates, and points the app at that blob with a read-only token. Azure stopped
accepting the creation of a Linux consumption Function App whose `WEBSITE_RUN_FROM_PACKAGE` is
a URL that redirects, and a GitHub release download URL always redirects.

One consequence worth knowing: **an installation keeps the package it was installed with.** The
release URL is read once, at install time. A later release does not reach an existing
installation -- redeploy to pick it up. Before September 2026 the app read that URL on every
cold start, so a new release did arrive on its own.

If the deployment fails at `triggerFirstRun`, the message says which step: an unreachable
package URL, a download that is not a readable zip, a package that never reached the container
the app reloads from, or an app that indexed no function within the poll window. The script
retries the settings read until its role assignment is effective, retries the upload up to
six times, and restarts the app once the package is staged -- writing the pointer alone was
measured not to make the host reload it. If the deployment fails, the diagnostic container
and its storage account stay in the resource group for 26 hours -- the documented ceiling --
so the log can still be read the next morning; delete them once you are done. A successful
deployment leaves neither behind.

It reports success only when both readings agree: the package pointer names a blob in the
`function-releases` container **and** the app has indexed a function. The count alone is not
enough -- an app whose package was staged somewhere else keeps reporting a function to Azure
Resource Manager while its host answers 503 from the next restart onwards.

A redeploy rewrites the package pointer, so it has to push again. If every attempt fails there,
the deployment reports a failure **and the app is left with no code** -- it does not keep
serving the package it had. Recovery does not need a rebuild: the previous package is still in
the `function-releases` container of the app's storage account, and pointing
`WEBSITE_RUN_FROM_PACKAGE` back at that blob brings the app back while you retry.
Rotating the storage account keys invalidates the read token inside that pointer, so the app
loses its code at the next restart -- issue a new token for the same blob and write the
pointer back.

One red row in **Resource group -> Deployments** is not ours and is harmless:
`Failure-Anomalies-Alert-Rule-Deployment-*`. Azure creates it by itself when the
Application Insights component appears, and it fails on a subscription that has
not registered the `Microsoft.AlertsManagement` provider (measured 7 Sep 2026).
Nothing in this template refers to it and the integration works without it;
register that provider if you want the smart-detection alert.

## Test

```bash
# Trigger manually via admin API
curl -X POST "https://<function-app>.azurewebsites.net/admin/functions/socradar_identity_import" \
  -H "x-functions-key: <master-key>" \
  -H "Content-Type: application/json" \
  -d '{}'

# Check results in Log Analytics
SOCRadar_Identity_CL | take 10
SOCRadar_Identity_Audit_CL | take 5
```
