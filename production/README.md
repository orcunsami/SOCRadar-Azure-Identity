# SOCRadar Identity Intelligence Integration for Microsoft Sentinel

Pulls leaked employee credentials from SOCRadar Identity Intelligence API and takes automated remediation actions in Microsoft Entra ID.

## Deployment

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Forcunsami%2FSOCRadar-Azure-Identity%2Fmaster%2Fproduction%2Fazuredeploy.json)

### Required Parameters

| Parameter | Description |
|-----------|-------------|
| SocradarIdentityApiKey | SOCRadar Identity Intelligence API key (pay-per-use, separate from Platform key) |
| MonitoredDomains | Comma-separated domains to monitor (e.g., `contoso.com,fabrikam.com`) |
| WorkspaceName | Microsoft Sentinel Log Analytics Workspace name |
| WorkspaceId | Workspace ID (from Agents management) |
| WorkspaceKey | Workspace primary key |
| EntraIdTenantId | Microsoft Entra ID tenant ID |
| EntraIdClientId | App Registration client ID |
| EntraIdClientSecret | App Registration client secret |

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
