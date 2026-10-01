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
| WorkspaceLocation | (deployment RG location) | Region of the workspace |
| SecurityGroupId | (empty) | Entra ID group for compromised users. Required for `EnableAddToGroup` |
| EnableRevokeSession | **true** | Revoke all sign-in sessions of a matched user. On by default, runs for every matched record |
| EnableAddToGroup | false | Add matched users to `SecurityGroupId`. Skipped (with a warning in the log) while the group is empty |
| EnablePasswordChange | false | Force a password change at next sign-in |
| EnableDisableAccount | false | Disable the account. Use with caution |
| EnableConfirmRisky | false | Confirm the user as compromised in Identity Protection (Entra ID P1/P2) |
| EnableCreateIncident | false | Create Microsoft Sentinel incidents for matched users. Needs Microsoft Sentinel on the workspace and a Sentinel role for the App Registration, see below |
| EnableLogPlaintextPassword | false | Write the password to Log Analytics when the API returns it unmasked. The API reference describes the value as masked |
| PollingIntervalHours | 6 | 1, 2, 3, 4, 6, 8, 12 or 24 |
| InitialLookbackMinutes | 600 | History to fetch on the first run |
| PackageUri | v1.0.0 release | Function package, see "How the code gets there" |

`EnableCreateIncident` signs in with the App Registration (not the managed identity). Give it
**Microsoft Sentinel Responder** (or Contributor) on the workspace. Without that role the
deployment is green and every incident call answers 403: the audit row counts it under
`error_count` and nothing else changes.

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

The Function App runs every `PollingIntervalHours` hours (6 by default) and once whenever the app starts.
Change the interval by redeploying; an edited `POLLING_SCHEDULE` app setting is overwritten by the next deployment.

A run that loses data is not clean: a failed Log Analytics write, a Graph error (401/403/429/5xx), a missing
Graph token or an unfinished SOCRadar read is counted in `error_count` and the checkpoint stays where it was,
so the next run reads the same window again. Records are repeated in that case; `record_id` identifies them.
Every repeat is another paid SOCRadar query, so a wrong Entra secret or a missing permission costs on every run until it is fixed.

The checkpoint is kept per domain. SOCRadar takes a start date, not a time, so the same day comes back on
every run; ids already returned for the checkpoint day are remembered and not processed twice.

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
| User-PasswordProfile.ReadWrite.All | Force password change |
| User.EnableDisableAccount.All | Disable account |
| IdentityRiskyUser.ReadWrite.All | Confirm compromised (requires P1/P2) |

Only grant the permissions of the actions you turn on. For administrator accounts, app-only password
and disable calls also need an Entra role assigned to the app's service principal.

### Workbook

Import `Workbooks/SOCRadar-Identity-Workbook.json` into Microsoft Sentinel for dashboard visualization.

### Not measured yet

- **Masked username.** The SOCRadar API reference describes `username` as "Masked username/email"
  (`tes****t@test.com`). The function looks the value up in Entra ID as a UPN, so a masked value matches
  no user. A production response has not been read (no Identity credit). Before relying on the Entra
  actions, run the Test below and check `SOCRadar_Identity_CL | summarize count() by entra_status_s`:
  if everything is `not_found` and `email_s` contains `****`, the matching needs another design.
- **Log Analytics ingestion.** Records are written with the HTTP Data Collector API. Microsoft ended
  support for it on 14 September 2026; ingestion still works. A move to the Logs Ingestion API
  (DCE + DCR) is not done.

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

## Test

```bash
# Trigger manually via admin API
curl -X POST "https://<function-app>.azurewebsites.net/admin/functions/socradar_identity_import" \
  -H "x-functions-key: <master-key>" \
  -H "Content-Type: application/json" \
  -d '{}'

# Check results in Log Analytics (the first run starts when the app starts)
SOCRadar_Identity_CL | take 10
SOCRadar_Identity_Audit_CL | take 5
```
